// Ports the Wireshark official example of the "FOO" dissector to Rust FFI.

use std::ffi::*;
use plugshark::*;

// Defines a C string in a constant form that's easier to use in Rust.
macro_rules! cstr {
    ($s:expr) => {
        concat!($s, "\0").as_ptr() as *const c_char
    };
}

// Plugin version string
#[no_mangle]
#[allow(non_upper_case_globals)]
#[used]
pub static plugin_version: [u8; 6] = [b'1', b'.', b'0', b'.', b'0', b'\0'];

// Major version of Wireshark that the plugin is built for
#[no_mangle]
#[allow(non_upper_case_globals)]
#[used]
pub static plugin_want_major: c_int = 4;

// Minor version of Wireshark that the plugin is built for
#[no_mangle]
#[allow(non_upper_case_globals)]
#[used]
pub static plugin_want_minor: c_int = 4;

// Entrypoint of the plugin, registers the plugin, its protocols, and all field type definitions.
#[no_mangle]
pub unsafe extern "C" fn plugin_register() {
    WiresharkPlugin::setup(|mut plugin| {
        let mut protocol =
            WiresharkProtocolDefinition::new(dissect_callback, "Test Protocol", "test", "test");

            
        // Add field types and how they will be displayed
        protocol.add_field_type(
            WiresharkFieldArgs::new("test.u32", "UInt32 Field")
            .with_field_type(FieldType::Uint32)
            .with_display(FieldDisplayType::BaseHex)
        );

        protocol.add_field_type(
            WiresharkFieldArgs::new("test.u8", "UInt8 Field")
            .with_field_type(FieldType::Uint8)
            .with_display(FieldDisplayType::BaseHex)
            .with_values(vec![
                (0x65, "Test1"),
                (0x66, "Test2"),
                (0x67, "Test3"),
                (0x68, "Test4"),
            ])
        );
 
        // Add match conditions that activate the dissector for a specific packet
        protocol.add_match_condition("udp.port", WiresharkMatchType::UInt32(1234));

        plugin.add_protocol(protocol);
    });
}

// Callback for dissection, called when a packet for this protocol is detected and dissected.
unsafe fn dissect_callback(mut tree: DissectorSubTree) {
    // Setting the info column
    tree.set_info_column("This is some info"); 

    // Pushing a single field into the dissector
    tree.add_field("test.u32", IndexPosition::Current(0), 4, FieldEncoding::LittleEndian);

    // Using the same field id multiple times
    tree.add_field("test.u8", IndexPosition::Current(0), 1, FieldEncoding::LittleEndian);
    tree.add_field("test.u8", IndexPosition::Current(0), 1, FieldEncoding::LittleEndian);
    tree.add_field("test.u8", IndexPosition::Current(0), 1, FieldEncoding::LittleEndian);

    // Appending text to the field
    let mut test = tree.add_field("test.u8", IndexPosition::Current(0), 1, FieldEncoding::LittleEndian);
    test.append_text(" (Some Appended Text)");
}
