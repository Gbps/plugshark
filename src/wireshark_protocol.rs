use bumpalo::Bump;
use epan_sys::*;
use std::{
    cell::{RefCell, RefMut}, collections::HashMap, ffi::*, io::Cursor, ptr::{null, null_mut}, rc::Rc
};

pub use crate::defines::*;
use bytestream::{ByteOrder, StreamReader};

pub type WiresharkProtocolRegistration = WiresharkProtocol;

// Contains all registered protocols for the plugin. The plugin global is a
// module-wide singleton.
static mut PLUGIN: Option<Rc<RefCell<WiresharkPlugin>>> = None;

// Plugin definition table.
static PROTO_PLUGIN: proto_plugin = proto_plugin {
    register_protoinfo: Some(proto_register_foo),
    register_handoff: Some(proto_reg_handoff),
};

// Get a RC reference to the global plugin object. We can only do this because
// the Wireshark plugin system assumes each module is a single threaded callback-oriented
// model. Where in C we would allocate everything as globals, here we allocate a single
// tracker object that is shared between all callbacks instead and reference count it
// to make Rust's borrow checker happy.
#[allow(static_mut_refs)]
unsafe fn get_global_plugin() -> Rc<RefCell<WiresharkPlugin>> {
    PLUGIN.as_ref().unwrap().clone()
}

pub struct WiresharkPlugin {
    // Holds all memory that must survive the lifetime of the plugin
    global_alloc: Rc<RefCell<Bump>>,

    // All protocol definitions which are pending to be registered
    protocol_definitions: Option<HashMap<String, WiresharkProtocolDefinition>>,

    // Holds all registered protocols
    protocols: HashMap<String, WiresharkProtocol>,

    // True if this plugin has been registered
    registered: bool,
}

impl WiresharkPlugin {
    // Create the plugin singleton
    fn new() -> Self {
        let obj = WiresharkPlugin {
            global_alloc: Rc::new(RefCell::new(Bump::new())),
            protocol_definitions: Some(HashMap::new()),
            protocols: HashMap::new(),
            registered: false,
        };

        return obj;
    }

    // Adds a new protocol to the plugin
    pub fn add_protocol(&mut self, def: WiresharkProtocolDefinition) {
        let protos = self.protocol_definitions.as_mut().unwrap();

        let exists = protos.contains_key(&def.id);
        if exists {
            panic!(
                "Protocol ID {} already registered, choose a different protocol ID.",
                def.id
            );
        }

        protos.insert(def.id.clone(), def);
    }

    // Gets the singleton instance of the plugin
    #[allow(static_mut_refs)]
    pub unsafe fn setup(setupfn: fn(RefMut<'_, WiresharkPlugin>)) {
        if let Some(_) = PLUGIN.as_ref() {
            panic!("Plugin already initialized, do not call setup() twice.");
        }

        PLUGIN = Some(Rc::new(RefCell::new(WiresharkPlugin::new())));

        // Create a RC reference to the global plugin
        let plugref = PLUGIN.as_ref().unwrap().clone();

        // Call the setup function
        setupfn(plugref.as_ref().borrow_mut());

        // Register the protocols
        plugref.as_ref().borrow_mut().register();
    }

    // Registers all protocols fields to Wireshark
    unsafe fn register(&mut self) {
        // Register this module as a plugin to Wireshark
        if self.registered {
            panic!("Plugin already registered, do not call register() twice.");
        }

        self.registered = true;
        proto_register_plugin(&PROTO_PLUGIN);
    }

    // Adds a protocol to the plugin that has been successfully registered
    fn add_registered_protocol(&mut self, id: &str, protocol: WiresharkProtocol) {
        self.protocols.insert(id.to_string(), protocol);
    }

    // Gets a protocol by its ID
    fn get_registered_protocol(&self, id: &str) -> &WiresharkProtocol {
        self.protocols.get(id).unwrap()
    }

    // Allocates a C string in the global allocator. These strings are guarenteed to be valid
    // for the lifetime of the protocol.
    fn alloc_string(&self, s: &str) -> *mut c_char {
        let alloc = self.global_alloc.clone();
        let borrow = alloc.as_ref().borrow();

        borrow.alloc_str(format!("{}\0", s).as_str()).as_ptr() as *mut c_char
    }

    // Allocates a flat C array of the given iterator and returns the pointer to the first element
    fn alloc_flat_c_array_iter<T, I>(&self, iter: I) -> *mut T
    where
        I: IntoIterator<Item = T>,
        I::IntoIter: ExactSizeIterator,
    {
        let alloc = self.global_alloc.clone();
        let borrow = alloc.as_ref().borrow();

        borrow.alloc_slice_fill_iter(iter).as_ptr() as *mut T
    }
}

// Used to describe the translation between a u32 value and a string
// to be displayed
type WiresharkFieldValueString<'a> = (u32, &'a str);

type WiresharkFieldValueStringOwned = (u32, String);

// Describes a field that is going to be registered with a protocol
pub struct WiresharkFieldArgs<'a> {
    // The unique ID to assign to the field, used in future calls
    id: &'a str,

    // The display name of the field
    name: &'a str,

    // The type of the field for display
    field_type: FieldType,

    // The way to display the field when rendered
    display: FieldDisplayType,

    // The bitmask to apply to the field
    bitmask: u64,

    // A list of value names to display next to the field. The dissector will
    // check all values in the vec and display the string value of one that matches.
    str_values: Option<Vec<WiresharkFieldValueString<'a>>>,
}

impl<'a> WiresharkFieldArgs<'a> {
    // Create a new field definition
    pub fn new(id: &'a str, name: &'a str) -> Self {
        Self {
            id: id,
            name: name,
            field_type: FieldType::None,
            display: FieldDisplayType::BaseNone,
            bitmask: 0x0,
            str_values: None,
        }
    }

    pub fn with_field_type(mut self, field_type: FieldType) -> Self {
        self.field_type = field_type;
        self
    }

    // Add a display type to the field definition
    pub fn with_display(mut self, display: FieldDisplayType) -> Self {
        self.display = display;
        self
    }

    // Add a bitmask to the field definition
    pub fn with_bitmask(mut self, bitmask: u64) -> Self {
        self.bitmask = bitmask;
        self
    }

    // Add a list of value names to display next to the field. The dissector will
    // check all values in the vec and display the string value of one that matches.
    pub fn with_values(mut self, values: Vec<WiresharkFieldValueString<'a>>) -> Self {
        self.str_values = Some(values);
        self
    }
}

struct WiresharkFieldDefinition {
    id: String,
    name: String,
    field_type: FieldType,
    display: FieldDisplayType,
    bitmask: u64,
    str_values: Option<Vec<WiresharkFieldValueStringOwned>>,
}

// Describes a protocol that is going to be registered with Wireshark
pub struct WiresharkProtocolDefinition {
    name: String,
    id: String,
    filter: String,
    dissector_fn: DissectorCallback,

    fields: Vec<WiresharkFieldDefinition>,
    match_definitions: Vec<WiresharkMatchDefinition>,
    num_ett_fields: usize,
}

impl WiresharkProtocolDefinition {
    // Create a new protocol definition
    pub fn new(dissector_fn: DissectorCallback, name: &str, id: &str, filter: &str) -> Self {
        Self {
            name: name.to_string(),
            id: id.to_string(),
            filter: filter.to_string(),
            dissector_fn: dissector_fn,
            fields: Vec::new(),
            match_definitions: Vec::new(),
            num_ett_fields: 1,
        }
    }

    // Add a field definition to the protocol
    pub fn add_field_type<'a>(&mut self, definition: WiresharkFieldArgs<'a>) {
        // If there is any str_values applied, convert them to WiresharkFieldValueStringOwned
        let str_values = definition.str_values.map(|values| {
            values
                .into_iter()
                .map(|(value, str)| (value, str.to_string()))
                .collect()
        });

        self.fields.push(WiresharkFieldDefinition {
            id: definition.id.to_string(),
            name: definition.name.to_string(),
            field_type: definition.field_type,
            display: definition.display,
            bitmask: definition.bitmask,
            str_values: str_values,
        });
    }

    // Add a condition by which the dissector will be run for a packet
    pub fn add_match_condition(&mut self, id: &str, match_type: WiresharkMatchType) {
        self.match_definitions.push(WiresharkMatchDefinition {
            id: id.to_string(),
            match_type: match_type,
        });
    }

    // Set the number of fields in the ETT for this protocol
    pub fn set_num_ett(&mut self, num_ett: usize) {
        if num_ett < 1 {
            panic!("ETT must have at least one field for the protocol subtree");
        }

        self.num_ett_fields = num_ett;
    }
}

// Describes a match condition for a dissector
struct WiresharkMatchDefinition {
    id: String,
    match_type: WiresharkMatchType,
}

// Describes a match condition for a dissector. When the condition is met, the dissector will be run.
pub enum WiresharkMatchType {
    UInt32(u32),
    String(String),
}

struct FieldHandle {
    handle: c_int,
    id: String,
    _ptr: *mut hf_register_info,
}

pub struct WiresharkProtocol {
    // Protocol handle
    proto_handle: c_int,

    // Holds the collapse state of the subtree
    ett_handles: Vec<c_int>,

    // Pointers to ett_handles vector above, registered to the protocol
    ett_handles_ptrs: Vec<*mut c_int>,

    // Unique ID of this protocol
    id: *const i8,

    // Function called to handle protocol dissection
    pub(crate) dissector_fn: DissectorCallback,

    // All registered fields for this protocol
    fields: Vec<FieldHandle>,

    // Pending match conditions for this protocol that have not yet been registered
    match_definitions: Option<Vec<WiresharkMatchDefinition>>,

    // A buffer that is used to format a rust string into a null terminated string before it is copied into an API function 
    nullterm_buffer: RefCell<Vec<u8>>,
}

// This callback is called when a packet is dissected for this protocol. It is passed a subtree
// where items can be added.
type DissectorCallback = unsafe fn(DissectorSubTree<'_>) -> ();

impl WiresharkProtocol {
    // Register a new protocol with the given name, ID, and filter
    // The ID is used to retrieve the protocol later and must be unique globally
    unsafe fn new(
        plugin: RefMut<'_, WiresharkPlugin>,
        match_definitions: Vec<WiresharkMatchDefinition>,
        dissector_fn: DissectorCallback,
        name: &str,
        id: &str,
        filter: &str,
        num_ett: usize,
    ) -> WiresharkProtocolRegistration {
        let mut obj = WiresharkProtocol {
            proto_handle: -1,
            ett_handles: Vec::new(),
            fields: Vec::new(),
            id: null(),
            dissector_fn: dissector_fn,
            match_definitions: Some(match_definitions),
            ett_handles_ptrs: Vec::with_capacity(num_ett),
            nullterm_buffer: RefCell::new(Vec::with_capacity(1024))
        };

        let id_str = plugin.alloc_string(id);
        obj.id = id_str;

        // Register the protocol itself
        obj.proto_handle = proto_register_protocol(
            plugin.alloc_string(name),
            id_str,
            plugin.alloc_string(filter),
        );
        assert!(obj.proto_handle >= 0);

        obj.ett_handles.resize(num_ett, -1);

        // Create a new vector that, for each ett_handles entry, has a pointer to the corresponding entry

        for i in 0..num_ett {
            let ptr = obj.ett_handles.as_mut_ptr().add(i);
            obj.ett_handles_ptrs.push(ptr);
        }

        // Register the protocol subtree array
        proto_register_subtree_array(obj.ett_handles_ptrs.as_ptr(), num_ett as i32);

        return obj;
    }

    // Add a field to the protocol
    unsafe fn register_field(
        &mut self,
        plugin: RefMut<'_, WiresharkPlugin>,
        name: &str,
        abbrev: &str,
        type_: FieldType,
        values: &Option<Vec<WiresharkFieldValueStringOwned>>,
        display: FieldDisplayType,
        bitmask: u64,
    ) {
        let mut values_ptr: *const _value_string = null();

        // Determine if we should allocate a values string array
        if let Some(values) = values {
            let values_str = values.iter().map(|value| _value_string {
                value: value.0,
                strptr: plugin.alloc_string(value.1.as_str()),
            });

            // Allocate the value strings table as a flat C array
            values_ptr = plugin.alloc_flat_c_array_iter(values_str);
        }

        let mut out_handle: c_int = -1;
        let obj = hf_register_info {
            p_id: &mut out_handle,
            hfinfo: header_field_info {
                name: plugin.alloc_string(name),
                abbrev: plugin.alloc_string(abbrev),
                type_: type_.to_u32(),
                display: display.to_i32(),
                strings: values_ptr as *const c_void,
                bitmask: bitmask,
                blurb: null(),
                id: -1,
                parent: 0,
                ref_type: hf_ref_type_HF_REF_TYPE_NONE,
                same_name_prev_id: -1,
                same_name_next: null_mut(),
            },
        };

        // Generate the C struct for the field
        let alloc: Rc<RefCell<Bump>> = plugin.global_alloc.clone();
        let borrow = alloc.as_ref().borrow_mut();
        let hf = borrow.alloc(obj);

        proto_register_field_array(self.proto_handle, hf, 1);
        assert!(out_handle != -1);

        // Keep a reference to the field by handle and name
        self.fields.push(
            FieldHandle {
                handle: out_handle,
                id: abbrev.to_string(),
                _ptr: hf,
            },
        );
    }

    // Get the handle to the protocol's ETT
    fn get_ett_handle(&self, idx: c_int) -> c_int {
        if idx < 0 {
            panic!("ETT handle index must be >= 0");
        }

        self.ett_handles.get(idx as usize).expect("ETT handle index out of bounds, use set_num_ett during protocol creation to set the number of ETT fields").clone()
    }

    // Get the handle to the protocol's ETT
    fn get_proto_handle(&self) -> c_int {
        self.proto_handle
    }

    // Get the handle to a field that has already been registered
    fn get_field_handle(&self, abbrev: &str) -> &FieldHandle {
        self.fields
            .iter()
            .find(|field| field.id == abbrev)
            .expect(format!("Field {} not registered in protocol.", abbrev).as_str())
    }

    // Start a dissector on this protocol, creating a top level subtree where items can be added
    pub(crate) unsafe fn start_dissector<'a>(
        &'a self,
        tvb: *mut tvbuff,
        pinfo: *mut _packet_info,
        tree: *mut _proto_node,
        start_index: c_int,
        ett_index: c_int,
        length: c_int,
    ) -> DissectorSubTree<'a> {
        return DissectorSubTree::new(
            self,
            self.get_proto_handle(),
            pinfo,
            tree,
            tvb,
            start_index,
            ett_index,
            length,
        );
    }

    // Convert a rust string to a temporary null terminated C string using a
    // reused internal buffer to add a null terminator to the string. Return
    // pointer be used within the context of the function that is calling it and
    // NEVER stored anywher, as it will go invalid as soon as another function
    // calls this.
    fn to_temp_cstring_fast(&self, s: &str) -> *const c_char {
        let mut bufref = self.nullterm_buffer.borrow_mut();
        bufref.resize(s.len() + 1, 0);
        bufref[0..s.len()].copy_from_slice(s.as_bytes());
        bufref[s.len()] = 0;
        bufref.as_ptr() as *const c_char
    }
}

pub struct TvBuff<'a> {
    // Pointer to the underlying tvbuff
    _tvb: *mut tvbuff,

    // The offset into the tvbuff
    _base_offset: u32,

    //A resolved slice of the tvbuff
    cursor: Cursor<&'a [u8]>,

    // Either little endian or big endian
    byteorder: ByteOrder,
}

impl<'a> TvBuff<'a> {
    // Wrap a tvbuff to access packet contents
    unsafe fn wrap(tvb: *mut tvbuff, offset: u32, byteorder: TvBuffByteOrder) -> Self {
        let captured_length = tvb_captured_length(tvb);
        let target_byte_order = match byteorder {
            TvBuffByteOrder::BigEndian => ByteOrder::BigEndian,
            TvBuffByteOrder::LittleEndian => ByteOrder::LittleEndian,
        };

        let slice_length = (captured_length as i32).checked_sub(offset as i32).unwrap();
        Self {
            _tvb: tvb,
            _base_offset: offset,
            cursor: Cursor::new(Self::resolve_slice_offset(tvb, offset as i32, slice_length)),
            byteorder: target_byte_order,
        }
    }

    // Convert the TvBuff to a slice of bytes starting at the given offset
    unsafe fn resolve_slice_offset(tvb: *mut tvbuff, offset: i32, length: i32) -> &'a [u8] {
        let ptr = tvb_get_ptr(tvb, offset, length);
        // If we're out of data, return an empty slice
        if ptr == null_mut() {
            return &[];
        }

        std::slice::from_raw_parts(ptr, length as usize)
    }

    // Read a sized object from the TvBuff
    pub fn read<T: StreamReader>(&mut self) -> std::io::Result<T> {
        T::read_from(&mut self.cursor, self.byteorder)
    }

    // The total length of the buffer
    pub fn length(&self) -> usize {
        self.cursor.get_ref().len()
    }

    // The remaining length of the buffer
    pub fn remaining(&self) -> usize {
        self.cursor.get_ref().len() - self.cursor.position() as usize
    }

    // Transform the buffer object into the slice starting from the current position of the cursor and of the given length.
    // If the length extends past the end of the buffer, it stops at the end of the buffer.
    pub fn into_slice(self, length: i32) -> &'a [u8] {
        let start: usize = self.cursor.position() as usize;
        let slic = self.cursor.into_inner();
        let mut end = start + length as usize;
        if end > slic.len() {
            end = slic.len();
        }

        return &slic[start..end];
    }
}

// Describes the index of where the field should be linked to the packet data
pub enum IndexPosition {
    // The field is linked to the start of the packet plus a given offset
    Start(i32),
    // The field is linked to current position in the packet plus a given offset
    Current(i32),
    // The field is linked to the end of the packet plus a given offset
    End(i32),
}

/// `ByteOrder` describes what order to write bytes to the buffer.
#[derive(Copy, Clone)]
pub enum TvBuffByteOrder {
    /// Represents big endian byte order (also called network endian).
    /// This is the default order if none is specified.
    BigEndian,
    /// Represents little endian byte order.
    LittleEndian,
}

pub struct DissectorSubTree<'a> {
    pinfo: *mut _packet_info,
    _parent_node: *mut _proto_node,
    top_item: *mut _proto_node,
    subtree_node: *mut _proto_node,
    tvb: *mut tvbuff,
    proto: &'a WiresharkProtocol,
    cur_index: c_int,
    length: c_int,
}

impl<'a> DissectorSubTree<'a> {
    // Create a new tree node for a dissector function
    // proto: The protocol being used
    // hf_handle: The handle of the field that should be used for the top level item of before the subtree begins
    // parent: The parent node of the new node
    // tvb: The tvbuff being dissected
    // start_index: The start index for this slice
    // length: The length of the buff
    unsafe fn new(
        proto: &'a WiresharkProtocol,
        hf_handle: c_int,
        pinfo: *mut _packet_info,
        parent: *mut _proto_node,
        tvb: *mut tvbuff,
        start_index: c_int,
        ett_index: c_int,
        length: c_int,
    ) -> Self {
        let new_item = proto_tree_add_item(parent, hf_handle, tvb, start_index, length, ENC_NA);
        let self_node: *mut _proto_node = proto_item_add_subtree(new_item, proto.get_ett_handle(ett_index));

        let obj = Self {
            _parent_node: parent,
            pinfo: pinfo,
            top_item: new_item,
            subtree_node: self_node,
            proto: proto,
            tvb: tvb,
            cur_index: start_index,
            length: length,
        };

        return obj;
    }

    // Convert an index position to an integer offset
    fn enum_to_index_position(&self, index: IndexPosition) -> i32 {
        match index {
            IndexPosition::Start(offset) => offset,
            IndexPosition::Current(offset) => self.cur_index + offset,
            IndexPosition::End(offset) => self.cur_index + self.length + offset,
        }
    }

    // Get the handle to a field that has already been registered
    pub fn get_field_handle(&self, field_id: &str) -> c_int {
        self.proto.get_field_handle(field_id).handle
    }

    // Return the data buffer at the beginning of this subtree
    pub unsafe fn get_buffer_start(&self, byteorder: TvBuffByteOrder) -> TvBuff {
        TvBuff::wrap(self.tvb, 0, byteorder)
    }

    // Return the data buffer at the current index within this subtree
    pub unsafe fn get_buffer_here<'b>(&self, byteorder: TvBuffByteOrder) -> TvBuff<'b> {
        TvBuff::wrap(self.tvb, self.cur_index.try_into().unwrap(), byteorder)
    }

    // Get a slice of the given length from the current index within this subtree.
    // If the length extends past the end of the buffer, it stops at the end of the buffer.
    pub unsafe fn get_slice_here<'b>(&self, length: i32) -> &'a [u8] {
        TvBuff::wrap(
            self.tvb,
            self.cur_index.try_into().unwrap(),
            TvBuffByteOrder::BigEndian,
        )
        .into_slice(length)
    }

    // Creates a new item in the tree at the given subindex and length of bytes. Does not increment the internal
    // index tracker.
    pub unsafe fn make_item_at_index(
        &mut self,
        field_id: &str,
        start_index: c_int,
        length: c_int,
        encoding: c_uint,
    ) {
        proto_tree_add_item(
            self.subtree_node,
            self.proto.get_field_handle(field_id).handle,
            self.tvb,
            start_index,
            length,
            encoding,
        );
    }

    // Push an item of the given length to the tree and increment the current index
    // by the length of the item.
    unsafe fn add_item(
        &mut self,
        field_id: &str,
        index: IndexPosition,
        length: c_int,
        encoding: c_uint,
    ) -> DissectorItem {
        let mut realized_length: i32 = 0;

        let item = proto_tree_add_item_ret_length(
            self.subtree_node,
            self.proto.get_field_handle(field_id).handle,
            self.tvb,
            self.enum_to_index_position(index),
            length,
            encoding,
            &mut realized_length,
        );

        // Add the actual length of the item to the current index so that the next item
        // is placed at the subsequent index
        self.cur_index += realized_length;

        DissectorItem::new(self, self.tvb, item)
    }

    // Push an integer item of the given length to the tree and increment the current index
    // by the length of the item.
    pub unsafe fn add_field(
        &mut self,
        field_id: &str,
        index: IndexPosition,
        length: c_int,
        encoding: FieldEncoding,
    ) -> DissectorItem {
        self.add_item(field_id, index, length, encoding.to_u32())
    }

    // Push a string item of the given length to the tree and increment the current index
    // by the length of the item.
    pub unsafe fn add_field_string(
        &mut self,
        field_id: &str,
        index: IndexPosition,
        length: c_int,
        encoding: StringFieldEncoding,
    ) -> DissectorItem {
        self.add_item(field_id, index, length, encoding.to_u32())
    }

    // Add a string field value which does not pull data from the packet or increment the index
    pub unsafe fn add_field_string_value(
        &mut self,
        field_handle: c_int,
        index: IndexPosition,
        length: c_int,
        value: &str,
    ) -> DissectorItem {
        let st = self.proto.to_temp_cstring_fast(value);
        let item = proto_tree_add_string(
            self.subtree_node,
            field_handle,
            self.tvb,
            self.enum_to_index_position(index),
            length,
            st,
        );
 
        DissectorItem::new(self, self.tvb, item)
    }

    // Add a uint field value which does not pull data from the packet or increment the index
    pub unsafe fn add_field_uint_value(
        &mut self,
        field_handle: c_int,
        index: IndexPosition,
        length: c_int,
        value: u32,
    ) -> DissectorItem {
        let item = proto_tree_add_uint(
            self.subtree_node,
            field_handle,
            self.tvb,
            self.enum_to_index_position(index),
            length,
            value,
        );
 
        DissectorItem::new(self, self.tvb, item)
    }

    // Add a uint64 field value which does not pull data from the packet or increment the index
    pub unsafe fn add_field_uint64_value(
        &mut self,
        field_handle: c_int,
        index: IndexPosition,
        length: c_int,
        value: u64,
    ) -> DissectorItem {
        let item = proto_tree_add_uint64(
            self.subtree_node,
            field_handle,
            self.tvb,
            self.enum_to_index_position(index),
            length,
            value,
        );
 
        DissectorItem::new(self, self.tvb, item)
    }

    // Create a new subtree item and return the subtree management object.
    // The field (given by field_id) will be inserted as a zero length" field and the subtree will be created with size "length" off of that. 
    pub unsafe fn push_subtree(&mut self, field_handle: c_int, index: IndexPosition, length: c_int, ett_index: c_int) -> DissectorSubTree {
        let subtree_tree = DissectorSubTree::new(
            self.proto,
            field_handle,
            self.pinfo,
            self.subtree_node,
            self.tvb,
            self.enum_to_index_position(index),
            ett_index,
            length,
        );

        self.cur_index += length;
        subtree_tree
    }
    // Create a new subtree item and return the subtree management object.
    // The field (given by field_id) will be inserted as a zero length field and subtree of length will be created off of that.
    // The subtree will be marked as generated, so it will show up in the UI but consume none of the packet data or modify the index.
    pub unsafe fn push_subtree_generated(&mut self, field_handle: c_int, index: IndexPosition, length: c_int, ett_index: c_int) -> DissectorSubTree {
        let mut subtree_tree = DissectorSubTree::new(
            self.proto,
            field_handle,
            self.pinfo,
            self.subtree_node,
            self.tvb,
            self.enum_to_index_position(index),
            ett_index,
            length,
        );

        subtree_tree.get_top_item().set_generated();

        subtree_tree
    }

    // Set the info column to the given string
    pub unsafe fn set_info_column(&mut self, info: &str) {
        let cinfo = (*self.pinfo).cinfo;
        let str = self.proto.to_temp_cstring_fast(info);
        col_add_str(cinfo, COL_INFO as i32, str);
    }

    // Get a reference to the top level item that the subtree is rooted off of
    pub unsafe fn get_top_item(&mut self) -> DissectorItem {
        DissectorItem::new(self, self.tvb, self.top_item)
    }
}

pub struct DissectorItem<'a> {
    subtree: &'a DissectorSubTree<'a>,
    tvb: *mut tvbuff,
    item: *mut _proto_node,
}

// Represents a single item in the dissector tree
impl<'a> DissectorItem<'a> {
    unsafe fn new(subtree: &'a DissectorSubTree, tvb: *mut tvbuff, item: *mut _proto_node) -> Self {
        Self {
            subtree: subtree,
            tvb: tvb,
            item: item,
        }
    }

    // Set the text of this item
    pub unsafe fn set_text(&mut self, text: &str) {
        let str = self.subtree.proto.to_temp_cstring_fast(text);
        proto_item_set_text(self.item, str);
    }

    // Append text to the end of this item
    pub unsafe fn append_text(&mut self, text: &str) {
        let str = self.subtree.proto.to_temp_cstring_fast(text);
        proto_item_append_text(self.item, str);
    }

    // Prepend text to the end of this item
    pub unsafe fn prepend_text(&mut self, text: &str) {
        let str = self.subtree.proto.to_temp_cstring_fast(text);
        proto_item_prepend_text(self.item, str);
    }

    // Set the length of this item
    pub unsafe fn set_len(&mut self, len: c_int) {
        proto_item_set_len(self.item, len);
    }

    // Set the end of this item
    pub unsafe fn set_end(&mut self, end: c_int) {
        proto_item_set_end(self.item, self.tvb, end);
    }

    // Get the length of this item
    pub unsafe fn get_len(&self) -> c_int {
        proto_item_get_len(self.item)
    }

    // Mark the item as generated, and therefore consuming no packet data
    pub unsafe fn set_generated(&mut self) {
        if !self.item.is_null() {
            let finfo = (*self.item).finfo;
            if !finfo.is_null() {
                (*finfo).flags |= FI_GENERATED;
            }
        }
    }

    // Mark the item as hidden, and therefore does not show in the UI but can still be filtered on
    pub unsafe fn set_hidden(&mut self) {
        if !self.item.is_null() {
            let finfo = (*self.item).finfo;
            if !finfo.is_null() {
                (*finfo).flags |= FI_HIDDEN;
            }
        }
    }
}

// Registers all protocol definitions. Callback from Wireshark.
#[no_mangle]
pub unsafe extern "C" fn proto_register_foo() {
    // Go through and call registration functions for each protocol definition

    let plugref = get_global_plugin();

    let definitions = plugref
        .as_ref()
        .borrow_mut()
        .protocol_definitions
        .take()
        .unwrap();

    for def in definitions.into_values() {
        // Create the protocol through the Wireshark API
        let mut proto = WiresharkProtocol::new(
            plugref.as_ref().borrow_mut(),
            def.match_definitions,
            def.dissector_fn,
            &def.name,
            &def.id,
            &def.filter,
            def.num_ett_fields
        );

        // Register all field definitions
        for field in def.fields.iter() {
            proto.register_field(
                plugref.as_ref().borrow_mut(),
                &field.name,
                &field.id,
                field.field_type,
                &field.str_values,
                field.display,
                field.bitmask,
            );
        }

        // Keep the protocol in the plugin
        plugref
            .as_ref()
            .borrow_mut()
            .add_registered_protocol(&def.id, proto);
    }
}

// Handoff function, called when dissector tables are loaded and wireshark determines what kind of dissector to use.
#[no_mangle]
pub unsafe extern "C" fn proto_reg_handoff() {
    let plugref = get_global_plugin();
    let mut temp_stor: Vec<(*mut dissector_handle, Vec<WiresharkMatchDefinition>)> = Vec::new();

    // For each protocol, grab their match definitions and create a dissector for them
    for proto in plugref.as_ref().borrow_mut().protocols.values_mut() {
        // Register the dissector's match conditions for this protocol
        let match_defs = proto.match_definitions.take().unwrap();

        let handle = create_dissector_handle(Some(dissection_dispatcher), proto.get_proto_handle());

        temp_stor.push((handle, match_defs));
    }

    // Now apply all matchers to the dissectors
    for (handle, match_defs) in temp_stor.iter() {
        for match_def in match_defs.iter() {
            let id_string = plugref
                .as_ref()
                .borrow_mut()
                .alloc_string(match_def.id.as_str());
            match &match_def.match_type {
                WiresharkMatchType::UInt32(value) => {
                    dissector_add_uint(id_string, *value, *handle);
                }
                WiresharkMatchType::String(value) => {
                    dissector_add_string(
                        id_string,
                        plugref.as_ref().borrow_mut().alloc_string(&value.as_str()),
                        *handle,
                    );
                }
            }
        }
    }
}

// The dissector function, called when a packet is dissected to any protocol registered in this framework.
pub unsafe extern "C" fn dissection_dispatcher(
    tvb: *mut tvbuff,
    pinfo: *mut _packet_info,
    tree: *mut _proto_node,
    _data: *mut c_void,
) -> c_int {
    // Don't call the dissector if we don't have a packet
    if pinfo.is_null() {
        return tvb_captured_length(tvb) as i32
    }

    let plugin = get_global_plugin();
    let plugref = plugin.as_ref().borrow();

    // Get the protocol that's being dissected
    let name = CStr::from_ptr((*pinfo).current_proto);
    let proto = plugref.get_registered_protocol(name.to_str().unwrap());

    // Clear the info column and set the protocol column to the name of the dissector
    let cinfo = (*pinfo).cinfo;
    col_set_str(cinfo, COL_PROTOCOL as i32, proto.id);
    col_clear(cinfo, COL_INFO as i32);

    let dissector = proto.start_dissector(tvb, pinfo, tree, 0, 0, -1);
    (proto.dissector_fn)(dissector);

    tvb_captured_length(tvb) as i32
}
