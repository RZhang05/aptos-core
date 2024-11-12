package main

import "C"

//export DoSomething
func DoSomething(str string) interface{} {
	return C.CString("hello")
}

func main() {}
