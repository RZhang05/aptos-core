// Copyright (c) The Diem Core Contributors
// Copyright (c) The Move Contributors
// SPDX-License-Identifier: Apache-2.0

//! Implementation of native functions for extern cadence.

use crate::natives::helpers::make_module_natives;
use move_binary_format::errors::PartialVMResult;
use move_vm_runtime::native_functions::{NativeContext, NativeFunction};
use move_vm_types::{
    loaded_data::runtime_types::Type,
    natives::function::NativeResult,
    pop_arg,
    values::{Value, VectorRef},
};
use std::{collections::VecDeque, sync::Arc};
use std::ffi::{CStr, CString, c_void};
use std::os::raw::c_char;

extern "C" {
    fn CreateComposite(
        moveLoc: GoString, 
        moveKind: u64, 
        moveQualifiedIdentifier: GoString, 
        moveAddress: GoString,
    ) -> u64;

    fn GetMember(key: u64, fieldName: GoString) -> GoInterface;

    fn SetMember(key: u64, fieldName: GoString, value: *const c_void);
}

#[repr(C)]
struct GoString {
    a: *const c_char,
    b: i64,
}

#[repr(C)]
struct GoInterface {
    t: *mut c_void,
    v: *mut c_void,
}

fn create_go_string(c_str: &CString) -> GoString {
    let ptr = c_str.as_ptr();
    let go_string = GoString {
        a: ptr,
        b: c_str.as_bytes().len() as i64,
    };
    return go_string
}

/***************************************************************************************************
 * native fun internal_create_composite
 *
 *   gas cost: null?
 *
 **************************************************************************************************/

fn native_create_composite(
    _context: &mut NativeContext,
    _ty_args: Vec<Type>,
    mut args: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    debug_assert!(args.len() == 3);
    let identifier_arg = pop_arg!(args, VectorRef);
    let identifier_ref = identifier_arg.as_bytes_ref();
    let identifier = CString::new(identifier_ref.as_slice()).expect("CString::new failed");
    let go_iden = create_go_string(&identifier);

    let kind = pop_arg!(args, u64);

    let address_arg = pop_arg!(args, VectorRef);
    let address_ref = address_arg.as_bytes_ref();
    let address = CString::new(address_ref.as_slice()).expect("CString::new failed");
    let go_address = create_go_string(&address);
    let go_loc = create_go_string(&address);

    let res = unsafe{ CreateComposite(go_loc, kind, go_iden, go_address) };

    NativeResult::map_partial_vm_result_one(0.into(), Ok(Value::u64(res)))
}

pub fn make_native_create_composite() -> NativeFunction {
    Arc::new(
        move |context, ty_args, args| -> PartialVMResult<NativeResult> {
            native_create_composite(context, ty_args, args)
        },
    )
}

/***************************************************************************************************
 * native fun internal_get_member
 *
 *   gas cost: null?
 *
 **************************************************************************************************/

 fn native_get_member(
    _context: &mut NativeContext,
    _ty_args: Vec<Type>,
    mut args: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    debug_assert!(args.len() == 2);
    let field_arg = pop_arg!(args, VectorRef);
    let field_ref = field_arg.as_bytes_ref();
    let field = CString::new(field_ref.as_slice()).expect("CString::new failed");
    let go_field = create_go_string(&field);

    let id = pop_arg!(args, u64);

    let res = unsafe{ GetMember(id, go_field) };

    let cstr = unsafe {CStr::from_ptr(res.v as *const _)}.to_string_lossy();

    let v = Value::vector_u8(cstr.bytes());

    NativeResult::map_partial_vm_result_one(0.into(), Ok(v))
}

pub fn make_native_get_member() -> NativeFunction {
    Arc::new(
        move |context, ty_args, args| -> PartialVMResult<NativeResult> {
            native_get_member(context, ty_args, args)
        },
    )
}

/***************************************************************************************************
 * native fun internal_set_member
 *
 *   gas cost: null?
 *
 **************************************************************************************************/
 fn native_set_member(
    _context: &mut NativeContext,
    _ty_args: Vec<Type>,
    mut args: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    debug_assert!(args.len() == 3);
    let value_arg = pop_arg!(args, VectorRef);
    let value_ref = value_arg.as_bytes_ref();
    let value = CString::new(value_ref.as_slice()).expect("CString::new failed");
    let go_value = create_go_string(&value);
    let go_ptr: *const GoString = &go_value;
    let rawptr = go_ptr as *const c_void;

    let field_arg = pop_arg!(args, VectorRef);
    let field_ref = field_arg.as_bytes_ref();
    let field = CString::new(field_ref.as_slice()).expect("CString::new failed");
    let go_field = create_go_string(&field);

    let id = pop_arg!(args, u64);

    unsafe{ SetMember(id, go_field, rawptr) };

    NativeResult::map_partial_vm_result_one(0.into(), Ok(Value::bool(true)))
}

pub fn make_native_set_member() -> NativeFunction {
    Arc::new(
        move |context, ty_args, args| -> PartialVMResult<NativeResult> {
            native_set_member(context, ty_args, args)
        },
    )
}

/***************************************************************************************************
 * module
 **************************************************************************************************/

pub fn make_all() -> impl Iterator<Item = (String, NativeFunction)> {
    let natives = [
        (
            "internal_create_composite",
            make_native_create_composite(),
        ),
        (
            "internal_get_member",
            make_native_get_member(),
        ),
        (
            "internal_set_member",
            make_native_set_member(),
        ),
    ];

    make_module_natives(natives)
}
