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
 
	 "github.com/onflow/atree"
 
	 "github.com/onflow/cadence/common"
 )

// Cadence needs to encode different kinds of objects in CBOR, for instance,
// dictionaries, structs, resources, etc.
//
// However, CBOR only provides one native map type, and no support
// for directly representing e.g. structs or resources.
//
// To be able to encode/decode such semantically different values,
// we define custom CBOR tags.

// !!! *WARNING* !!!
//
// Only add new fields to encoded structs by
// appending new fields with the next highest key.
//
// DO *NOT* REPLACE EXISTING FIELDS!

const CBORTagBase = 128

// !!! *WARNING* !!!
//
// Only add new types by:
// - replacing existing placeholders (`_`) with new types
// - appending new types
//
// Only remove types by:
// - replace existing types with a placeholder `_`
//
// DO *NOT* REPLACE EXISTING TYPES!
// DO *NOT* ADD NEW TYPES IN BETWEEN!

const (
	CBORTagVoidValue = CBORTagBase + iota
	_                // DO *NOT* REPLACE. Previously used for dictionary values
	CBORTagSomeValue
	CBORTagAddressValue
	CBORTagCompositeValue
	CBORTagTypeValue
	_ // DO *NOT* REPLACE. Previously used for array values
	CBORTagStringValue
	CBORTagCharacterValue
	CBORTagSomeValueWithNestedLevels
	_
	_
	_
	_
	_
	_
	_
	_
	_
	_
	_
	_
	_
	_

	// Int*
	CBORTagIntValue
	CBORTagInt8Value
	CBORTagInt16Value
	CBORTagInt32Value
	CBORTagInt64Value
	CBORTagInt128Value
	CBORTagInt256Value
	_

	// UInt*
	CBORTagUIntValue
	CBORTagUInt8Value
	CBORTagUInt16Value
	CBORTagUInt32Value
	CBORTagUInt64Value
	CBORTagUInt128Value
	CBORTagUInt256Value
	_

	// Word*
	_
	CBORTagWord8Value
	CBORTagWord16Value
	CBORTagWord32Value
	CBORTagWord64Value
	CBORTagWord128Value
	CBORTagWord256Value
	_

	// Fix*
	_
	_ // future: Fix8
	_ // future: Fix16
	_ // future: Fix32
	CBORTagFix64Value
	_ // future: Fix128
	_ // future: Fix256
	_

	// UFix*
	_
	_ // future: UFix8
	_ // future: UFix16
	_ // future: UFix32
	CBORTagUFix64Value
	_ // future: UFix128
	_ // future: UFix256
	_

	// Locations
	CBORTagAddressLocation
	CBORTagStringLocation
	CBORTagIdentifierLocation
	CBORTagTransactionLocation
	CBORTagScriptLocation
	_
	_
	_

	// Storage

	CBORTagPathValue
	// Deprecated: CBORTagPathCapabilityValue
	CBORTagPathCapabilityValue
	_ // DO NOT REPLACE! used to be used for storage references
	// Deprecated: CBORTagPathLinkValue
	CBORTagPathLinkValue
	CBORTagPublishedValue
	// Deprecated: CBORTagAccountLinkValue
	CBORTagAccountLinkValue
	CBORTagStorageCapabilityControllerValue
	CBORTagAccountCapabilityControllerValue
	CBORTagCapabilityValue
	_
	_
	_

	// Static Types
	CBORTagPrimitiveStaticType
	CBORTagCompositeStaticType
	CBORTagInterfaceStaticType
	CBORTagVariableSizedStaticType
	CBORTagConstantSizedStaticType
	CBORTagDictionaryStaticType
	CBORTagOptionalStaticType
	CBORTagReferenceStaticType
	CBORTagIntersectionStaticType
	CBORTagCapabilityStaticType
	CBORTagUnauthorizedStaticAuthorization
	CBORTagEntitlementMapStaticAuthorization
	CBORTagEntitlementSetStaticAuthorization
	CBORTagInaccessibleStaticAuthorization

	_
	_
	_
	_

	CBORTagInclusiveRangeStaticType

	// !!! *WARNING* !!!
	// ADD NEW TYPES *BEFORE* THIS WARNING.
	// DO *NOT* ADD NEW TYPES AFTER THIS LINE!
	CBORTag_Count
)


// compositeTypeInfo
type compositeTypeInfo struct {
	location            common.Location
	qualifiedIdentifier string
	kind                common.CompositeKind
}

func NewCompositeTypeInfo(
	location common.Location,
	qualifiedIdentifier string,
	kind common.CompositeKind,
) compositeTypeInfo {
	return compositeTypeInfo{
		location:            location,
		qualifiedIdentifier: qualifiedIdentifier,
		kind:                kind,
	}
}

var _ atree.TypeInfo = compositeTypeInfo{}

const encodedCompositeTypeInfoLength = 3

func (c compositeTypeInfo) IsComposite() bool {
	return true
}

func (c compositeTypeInfo) Copy() atree.TypeInfo {
	// Return c as is because c is a value type.
	return c
}

func (c compositeTypeInfo) Encode(e *cbor.StreamEncoder) error {
	err := e.EncodeRawBytes([]byte{
		// tag number
		0xd8, CBORTagCompositeValue,
		// array, 3 items follow
		0x83,
	})
	if err != nil {
		return err
	}

	err = encodeLocation(e, c.location)
	if err != nil {
		return err
	}

	err = e.EncodeString(c.qualifiedIdentifier)
	if err != nil {
		return err
	}

	err = e.EncodeUint64(uint64(c.kind))
	if err != nil {
		return err
	}

	return nil
}

func (c compositeTypeInfo) Equal(o atree.TypeInfo) bool {
	other, ok := o.(compositeTypeInfo)
	return ok &&
		c.location == other.location &&
		c.qualifiedIdentifier == other.qualifiedIdentifier &&
		c.kind == other.kind
}