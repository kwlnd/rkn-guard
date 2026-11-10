package service

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/Flecksis/rkn-guard/internal/domain"
)

func TestNormalizeBan(t *testing.T) {
	for in, want := range map[string]string{
		"192.0.2.7": "192.0.2.7", " 192.0.2.7/32 ": "192.0.2.7", "192.0.2.9/24": "192.0.2.0/24",
		"2001:DB8::1": "2001:db8::1", "2001:db8::/32": "2001:db8::/32",
	} {
		if got, err := NormalizeBan(in); err != nil || got != want {
			t.Errorf("%q: %q %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "1.2.3", "0.0.0.0/0", "::/0", "fe80::1%eth0", "::ffff:1.2.3.4", "1.2.3.4/33", "a.b.c.d"} {
		if _, err := NormalizeBan(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestBanStoreMigratesAndPersists(t *testing.T) {
	dir := t.TempDir()
	legacy := filepath.Join(dir, "manual.list")
	// Старое меню могло записать мусор и дубли.
	if err := os.WriteFile(legacy, []byte("192.0.2.7\n192.0.2.7\nмусор\n2001:db8::1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	store := &BanStore{Path: filepath.Join(dir, "state", "bans.list"), LegacyPath: legacy}
	list, err := store.List()
	if err != nil || !reflect.DeepEqual(list, []string{"192.0.2.7", "2001:db8::1"}) {
		t.Fatal(list, err)
	}
	added, err := store.Add([]string{"192.0.2.7", "198.51.100.0/24"})
	if err != nil || !reflect.DeepEqual(added, []string{"198.51.100.0/24"}) {
		t.Fatal(added, err)
	}
	if _, err := os.Stat(legacy); !os.IsNotExist(err) {
		t.Fatal("legacy file not removed after migration")
	}
	removed, err := store.Remove([]string{"192.0.2.7/32", "203.0.113.1"})
	if err != nil || !reflect.DeepEqual(removed, []string{"192.0.2.7"}) {
		t.Fatal(removed, err)
	}
	list, _ = store.List()
	if !reflect.DeepEqual(list, []string{"198.51.100.0/24", "2001:db8::1"}) {
		t.Fatal(list)
	}
}

func TestMergeBansSplitsFamilies(t *testing.T) {
	got := MergeBans(&domain.NetworkList{IPv4Subnets: []string{"192.0.2.0/24"}}, []string{"192.0.2.5", "2001:db8::1", "198.51.100.1"})
	if !reflect.DeepEqual(got.IPv4Subnets, []string{"192.0.2.0/24", "198.51.100.1/32"}) || !reflect.DeepEqual(got.IPv6Subnets, []string{"2001:db8::1/128"}) {
		t.Fatal(got)
	}
}
