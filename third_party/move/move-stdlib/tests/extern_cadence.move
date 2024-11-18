#[test_only]
module std::cadence_tests {
    use std::string;
    use std::extern_cadence;

    #[test]
    fun test_full_composite() {
        let iden = string::utf8(b"foo");
        let address = string::utf8(b"0x1");
        let obj = extern_cadence::create_composite(&address, 0, &iden);
        let field = string::utf8(b"a");
        let value = string::utf8(b"bar");
        extern_cadence::set_member(&obj, &field, &value);
        let field2 = string::utf8(b"a");
        let result = extern_cadence::get_member(&obj, &field);
        assert!(result == string::utf8(b"bar"), 22);
    }
}
