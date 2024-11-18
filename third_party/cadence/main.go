package main

import (
	"C"

	"github.com/onflow/cadence/common"

	"unsafe"
)

// global unsafe pointer storage
var composites = make(map[uintptr]*CompositeValue)
var runtime = NewMoveRuntime()

//export GetMember
func GetMember(key uintptr, fieldName string) interface{} {
	var v = composites[key]

	var string_result string = v.GetMember(
		fieldName,
	).(string)
	
	return C.CString(string_result)
}

//export SetMember
func SetMember(key uintptr, fieldName string, value unsafe.Pointer) {
	var v = composites[key]

	var stringValue = *(*string)(value)

	v.SetMember(
		fieldName,
		stringValue,
	)
}

//export EmptyFunc
func EmptyFunc() {}

//export CreateComposite
func CreateComposite(
	moveLoc string,
	moveKind uint,
	moveQualifiedIdentifier string,
	//fields []interpreter.CompositeField,
	moveAddress string,
) uintptr {
	var location = NewAddressLocationFromHex(moveAddress, moveQualifiedIdentifier)
	var kind common.CompositeKind =  common.CompositeKind(moveKind)
	var address common.Address = common.ZeroAddress

	var go_struct = NewCompositeValue(
		runtime,
		location,
		moveQualifiedIdentifier,
		kind,
		//fields
		address,
	)

	// this struct is allocated and stored on the go side
	// cgo does not allow passing a pointer to go memory to C
	// so instead we abstract away this pointer
	// but 100% memory safe
	// https://groups.google.com/g/golang-nuts/c/uW9ehN4uXrM
	key := uintptr(unsafe.Pointer(go_struct))
	composites[key] = go_struct
	return key
}

func main() {}
