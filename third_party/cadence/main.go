package main

import (
	"C"

	"github.com/onflow/cadence/common"
)

//export DoSomething
func DoSomething(str string) interface{} {
	return C.CString("hello")
}

//export GetMember
func GetMember(v interface{}) interface{} {
	// v is expected to be a compositeValue
	return C.CString("does something")
}

//export CreateComposite
func CreateComposite(
	moveLoc int,
	moveKind int,
	moveQualifiedIdentifier string,
	//fields []interpreter.CompositeField,
	moveAddress int,
) interface{} {
	// derive these fields from params
	var runtime *MoveRuntime
	var location common.Location
	var kind common.CompositeKind
	var address common.Address

	return NewCompositeValue(
		runtime,
		location,
		moveQualifiedIdentifier,
		kind,
		//fields
		address,
	)
}

func main() {}
