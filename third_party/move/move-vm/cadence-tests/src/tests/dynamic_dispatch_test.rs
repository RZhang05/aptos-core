use move_vm_runtime::{
    module_traversal::*, 
    move_vm::MoveVM, 
    AsUnsyncModuleStorage, 
    RuntimeEnvironment,
    session::SerializedReturnValues,
};
use move_core_types::{
    account_address::AccountAddress,
    identifier::Identifier,
    value::{serialize_values, MoveValue}, // value (aptos) instead of runtime_value (sui)
};
use move_vm_test_utils::InMemoryStorage;
use move_vm_types::gas::UnmeteredGasMeter;
use move_binary_format::{
    errors::VMResult, 
    CompiledModule,
    binary_views::BinaryIndexedView,
    file_format::Bytecode,
};
use move_disassembler::disassembler::{Disassembler, DisassemblerOptions};
use move_ir_types::location::Spanned;
use crate::compiler::{as_module, compile_units};

const TEST_ADDR: AccountAddress = AccountAddress::new([42; AccountAddress::LENGTH]);

pub fn print_bytecode(module: &CompiledModule) {
    let mut disassembler_options = DisassemblerOptions::new();
    disassembler_options.print_code = true;
    disassembler_options.only_externally_visible = false;
    disassembler_options.print_basic_blocks = true;
    disassembler_options.print_locals = true;
    disassembler_options.print_bytecode_stats = true;

    let no_loc = Spanned::unsafe_no_loc(()).loc;
    let mut disassembler = Disassembler::from_view(BinaryIndexedView::Module(module), no_loc).expect("Disassembler created");
    let disassemble_string = disassembler.disassemble().expect("Unable to disassemble");

    println!("{}", disassemble_string);
}

pub fn insert_magic_bytecode(module: &mut CompiledModule) {
    // assume code and function exists
    let mut code = &mut module.function_defs[2].code.as_mut().unwrap().code;

    // append bytecode
    code.insert(1, Bytecode::Magic);
    code[2] = Bytecode::Ret;
}

pub fn load_edit_module() -> CompiledModule {
    let code = r#"
        module {{ADDR}}::M {
            public fun a(): u64 {
                return 100
            }
            public fun b(): u64 {
                return 200
            }
            public fun foo(value: u64): u64 {
                return value
            }
        }
    "#;
    let code = code.replace("{{ADDR}}", &format!("0x{}", TEST_ADDR.to_hex()));
    
    let mut units = compile_units(&code).unwrap();
    let mut module = as_module(units.pop().unwrap());
    let mut blob = vec![];
    module.serialize(&mut blob).unwrap();
    print_bytecode(&module);

    // edit bytecode now
    insert_magic_bytecode(&mut module);

    // reserialize and print again for sanity check
    let mut module_blob = vec![];
    module.serialize(&mut module_blob).unwrap();

    let updated_module = CompiledModule::deserialize(&module_blob).expect("success");
    print_bytecode(&updated_module);

    return updated_module;
}

#[test]
fn test_dynamic_dispatch() {
    let module = load_edit_module();
    let mut blob = vec![];
    module.serialize(&mut blob).unwrap();

    let mut storage = InMemoryStorage::new();
    let module_id = module.self_id();
    storage.add_module_bytes(module_id.address(), module_id.name(), blob.into());

    let runtime_environment = RuntimeEnvironment::new(vec![]);
    let vm = MoveVM::new_with_runtime_environment(&runtime_environment);
    let mut sess = vm.new_session(&storage);

    let fun_name = Identifier::new("foo").unwrap();

    let module_storage = storage.as_unsync_module_storage(runtime_environment);

    let traversal_storage = TraversalStorage::new();

    let mut param = 0;

    let SerializedReturnValues {
        return_values,
        mutable_reference_outputs: _,
    } = sess.
    execute_function_bypass_visibility(
        &module.self_id(),
        &fun_name,
        vec![],
        serialize_values(&vec![MoveValue::U64(param)]),
        &mut UnmeteredGasMeter,
        &mut TraversalContext::new(&traversal_storage),
        &module_storage,
    ).unwrap();

    let mut result = MoveValue::simple_deserialize(&return_values[0].0, &return_values[0].1)
        .unwrap();

    assert_eq!(result, MoveValue::U64(100));

    param = 6;

    let SerializedReturnValues {
        return_values,
        mutable_reference_outputs: _,
    } = sess.
    execute_function_bypass_visibility(
        &module.self_id(),
        &fun_name,
        vec![],
        serialize_values(&vec![MoveValue::U64(param)]),
        &mut UnmeteredGasMeter,
        &mut TraversalContext::new(&traversal_storage),
        &module_storage,
    ).unwrap();

    result = MoveValue::simple_deserialize(&return_values[0].0, &return_values[0].1)
        .unwrap();

    assert_eq!(result, MoveValue::U64(200));
}