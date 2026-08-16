package grpcapi

import (
	"strings"
	"testing"
)

const shopProto = `
syntax = "proto3";
package shop.v1;
import "google/protobuf/empty.proto";

message Order { string ref = 1; int32 total = 2; }
message GetOrderRequest { string ref = 1; }

service Orders {
  rpc GetOrder(GetOrderRequest) returns (Order);
  rpc ListOrders(google.protobuf.Empty) returns (stream Order);
  rpc Upload(stream Order) returns (Order);
  rpc Chat(stream Order) returns (stream Order);
}
service Health { rpc Check(google.protobuf.Empty) returns (google.protobuf.Empty); }
`

func TestParseCollectsEveryMethodAndStreamingMode(t *testing.T) {
	schema, err := Parse(shopProto)
	if err != nil {
		t.Fatal(err)
	}
	if schema.Proto != shopProto {
		t.Fatal("the source must be kept verbatim: the ARM schema resource returns what was imported")
	}
	want := map[string][2]bool{
		"/shop.v1.Orders/GetOrder":   {false, false},
		"/shop.v1.Orders/ListOrders": {false, true},
		"/shop.v1.Orders/Upload":     {true, false},
		"/shop.v1.Orders/Chat":       {true, true},
		"/shop.v1.Health/Check":      {false, false},
	}
	for path, modes := range want {
		method, ok := schema.Lookup(path)
		if !ok {
			t.Fatalf("%s missing from the schema", path)
		}
		if method.ClientStreaming != modes[0] || method.ServerStreaming != modes[1] {
			t.Errorf("%s streaming = client:%v server:%v, want %v", path, method.ClientStreaming, method.ServerStreaming, modes)
		}
		if method.Path() != path {
			t.Errorf("Path() = %q, want %q", method.Path(), path)
		}
	}
	if _, ok := schema.Lookup("/shop.v1.Orders/Absent"); ok {
		t.Fatal("an undefined method must not resolve")
	}
	if got := len(schema.Methods()); got != len(want) {
		t.Fatalf("Methods() = %d entries, want %d", got, len(want))
	}
	if names := strings.Join(schema.ServiceNames(), ","); names != "shop.v1.Health,shop.v1.Orders" {
		t.Fatalf("ServiceNames = %q, want both, sorted", names)
	}
}

func TestParseRejectsUnusableSchemas(t *testing.T) {
	for name, source := range map[string]string{
		"empty":          "   ",
		"not proto":      "this is not protobuf",
		"no service":     `syntax = "proto3"; package a; message M { string x = 1; }`,
		"unknown type":   `syntax = "proto3"; package a; service S { rpc R(Missing) returns (Missing); }`,
		"missing import": `syntax = "proto3"; package a; import "nope.proto"; service S { rpc R(X) returns (X); }`,
	} {
		if _, err := Parse(source); err == nil {
			t.Errorf("Parse(%s) accepted an unusable schema", name)
		}
	}
}
