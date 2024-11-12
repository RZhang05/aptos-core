/*
 * Cadence - The resource-oriented smart contract programming language
 *
 * Copyright Dapper Labs, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

 package main

 import (
	 "github.com/fxamacker/cbor/v2"
 
	 "github.com/onflow/cadence/common"
	 "github.com/onflow/cadence/errors"
	 "github.com/onflow/cadence/interpreter"
 )
 
 func encodeLocation(e *cbor.StreamEncoder, l common.Location) error {
	 if l == nil {
		 return e.EncodeNil()
	 }
 
	 switch l := l.(type) {
 
	 case common.StringLocation:
		 // common.StringLocation is encoded as
		 // cbor.Tag{
		 //		Number:  CBORTagStringLocation,
		 //		Content: string(l),
		 // }
		 err := e.EncodeRawBytes([]byte{
			 // tag number
			 0xd8, interpreter.CBORTagStringLocation,
		 })
		 if err != nil {
			 return err
		 }
 
		 return e.EncodeString(string(l))
 
	 case common.IdentifierLocation:
		 // common.IdentifierLocation is encoded as
		 // cbor.Tag{
		 //		Number:  CBORTagIdentifierLocation,
		 //		Content: string(l),
		 // }
		 err := e.EncodeRawBytes([]byte{
			 // tag number
			 0xd8, interpreter.CBORTagIdentifierLocation,
		 })
		 if err != nil {
			 return err
		 }
 
		 return e.EncodeString(string(l))
 
	 case common.AddressLocation:
		 // common.AddressLocation is encoded as
		 // cbor.Tag{
		 //		Number: CBORTagAddressLocation,
		 //		Content: []any{
		 //			encodedAddressLocationAddressFieldKey: []byte{l.Address.Bytes()},
		 //			encodedAddressLocationNameFieldKey:    string(l.Name),
		 //		},
		 // }
		 // Encode tag number and array head
		 err := e.EncodeRawBytes([]byte{
			 // tag number
			 0xd8, interpreter.CBORTagAddressLocation,
			 // array, 2 items follow
			 0x82,
		 })
		 if err != nil {
			 return err
		 }
 
		 // Encode address at array index encodedAddressLocationAddressFieldKey
		 err = e.EncodeBytes(l.Address.Bytes())
		 if err != nil {
			 return err
		 }
 
		 // Encode name at array index encodedAddressLocationNameFieldKey
		 return e.EncodeString(l.Name)
 
	 case common.TransactionLocation:
		 // common.TransactionLocation is encoded as
		 // cbor.Tag{
		 //		Number: CBORTagTransactionLocation,
		 //		Content: []byte(l),
		 // }
		 // Encode tag number and array head
		 err := e.EncodeRawBytes([]byte{
			 // tag number
			 0xd8, interpreter.CBORTagTransactionLocation,
		 })
		 if err != nil {
			 return err
		 }
 
		 return e.EncodeBytes(l[:])
 
	 case common.ScriptLocation:
		 // common.ScriptLocation is encoded as
		 // cbor.Tag{
		 //		Number: CBORTagScriptLocation,
		 //		Content: []byte(l),
		 // }
		 // Encode tag number and array head
		 err := e.EncodeRawBytes([]byte{
			 // tag number
			 0xd8, interpreter.CBORTagScriptLocation,
		 })
		 if err != nil {
			 return err
		 }
 
		 return e.EncodeBytes(l[:])
 
	 default:
		 return errors.NewUnexpectedError("unsupported location: %T", l)
	 }
 }