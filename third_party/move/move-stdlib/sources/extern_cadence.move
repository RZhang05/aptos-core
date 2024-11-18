/// The `extern_cadence` module defines the `ExternCadence` type which represents an external type in cadence
module std::extern_cadence {
  use std::string;

  /// An `ExternCadence` type simply holds an id to interface with cadence.
  struct ExternCadence has copy, drop, store {
    id: u64,
  }

  /// Creates a new ExternCadence object.
  public fun create_composite(address: &string::String, kind: u64, identifier: &string::String): ExternCadence {
    let id = internal_create_composite(string::bytes(address), kind, string::bytes(identifier));
    ExternCadence{id}
  }

  /// Get the value of an external member with string type.
  public fun get_member(e: &ExternCadence, field_name: &string::String): string::String {
    let res = internal_get_member(e.id, string::bytes(field_name));
    string::utf8(res)
  }

  /// Set the value of an external member with string type.
  public fun set_member(e: &ExternCadence, field_name: &string::String, value: &string::String) {
    internal_set_member(e.id, string::bytes(field_name), string::bytes(value));
  }

  // Native API
  native fun internal_create_composite(address: &vector<u8>, kind: u64, identifier: &vector<u8>): u64;
  native fun internal_get_member(id: u64, field_name: &vector<u8>): vector<u8>;
  native fun internal_set_member(id: u64, field_name: &vector<u8>, value: &vector<u8>): bool;
}
