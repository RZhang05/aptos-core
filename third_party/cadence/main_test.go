package main

import (
	"testing"

	"github.com/onflow/cadence/common"
)

func BenchmarkGoCompositeCreation(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	var runtime = NewMoveRuntime()

	for i := 0; i < b.N; i++ {
		var v = NewCompositeValue(
			runtime,
			NewAddressLocationFromHex("0x1", "Foo"),
			"Foo",
			common.CompositeKind(0),
			common.ZeroAddress,
		)
		v.SetMember("a", "some random string")
		v.GetMember("a")
	}
}