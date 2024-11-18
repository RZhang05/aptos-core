#[test_only]
module std::cadence_tests {
    use std::string;
    use std::extern_cadence;

    #[test]
    fun test_create() {
        let iden = string::utf8(b"foo");
        let address = string::utf8(b"0x1");
        let obj = extern_cadence::create_composite(&address, 0, &iden);
    }
}
