/// The `extern_cadence` module defines the `ExternCadence` type which represents an external type in cadence
module std::extern_cadence {
    use std::string;

    /// An `ExternCadence` type simply holds an id to interface with cadence.
    struct ExternCadence has copy, drop, store {
        id: u64,
    }

    /// Creates a new ExternCadence object.
    public fun createExtern(address: &String, kind: u64, identifier: &String): ExternCadence {
        ExternCadence{internal_create_composite(address.bytes(), kind, identifier.bytes())}
    }

    /// Get the value of an external member with string type.
    public fun get_member(e: &ExternCadence, field_name: &String): String {
        let res = internal_get_member(e.id, field_name.bytes());
        return String::utf8(res);
    }

    /// Set the value of an external member with string type.
    public fun set_member(e: &ExternCadence, field_name: &String, value: &String) {
        internal_set_member(e.id, field_name.bytes(), value.bytes());
    }

    // Native API
    native fun internal_create_composite(address: &vector<u8>, kind: u64, identifier: &vector<u8>): u64;
    native fun internal_get_member(id: u64, field_name: &vector<u8>): vector<u8>;
    native fun internal_set_member(id: u64, field_name: &vector<u8>, value: &vector<u8>): bool;
}
