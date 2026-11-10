package service

import (
	"reflect"
	"testing"

	"github.com/Flecksis/rkn-guard/internal/domain"
)

func TestCollapseNetworks(t *testing.T) {
	in := &domain.NetworkList{
		IPv4Subnets: []string{
			"109.120.180.0/22", "109.120.180.0/23", "109.120.182.0/23", // вложенные
			"10.0.0.0/25", "10.0.0.128/25", // соседние половины
			"10.0.1.0/24",                  // и ещё одна половина сверху
			"192.0.2.7/32", "192.0.2.7/32", // дубль
			"198.51.100.0/24",
		},
		IPv6Subnets: []string{"2001:db8::/33", "2001:db8:8000::/33", "2001:db8::1/128"},
	}
	got := CollapseNetworks(in)
	want4 := []string{"10.0.0.0/23", "109.120.180.0/22", "192.0.2.7/32", "198.51.100.0/24"}
	want6 := []string{"2001:db8::/32"}
	if !reflect.DeepEqual(got.IPv4Subnets, want4) || !reflect.DeepEqual(got.IPv6Subnets, want6) {
		t.Fatalf("got %v %v", got.IPv4Subnets, got.IPv6Subnets)
	}
}

func TestCollapseKeepsUnrelatedNeighbours(t *testing.T) {
	// 10.0.1.0/24 и 10.0.2.0/24 соседи, но не половины одного /23.
	got := CollapseNetworks(&domain.NetworkList{IPv4Subnets: []string{"10.0.1.0/24", "10.0.2.0/24"}})
	if len(got.IPv4Subnets) != 2 {
		t.Fatal(got.IPv4Subnets)
	}
}
