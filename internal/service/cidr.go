package service

import (
	"net/netip"
	"sort"

	"github.com/Flecksis/rkn-guard/internal/domain"
)

// CollapseNetworks убирает подсети, вложенные в другие, и сливает соседние
// половины в общий префикс. Набор блокируемых адресов не меняется, а записей
// в ipset становится меньше: разные источники часто публикуют пересекающиеся диапазоны.
func CollapseNetworks(networks *domain.NetworkList) *domain.NetworkList {
	result := domain.NewNetworkList()
	for _, subnet := range collapsePrefixes(parsePrefixes(networks.IPv4Subnets)) {
		result.Add(subnet.String(), false)
	}
	for _, subnet := range collapsePrefixes(parsePrefixes(networks.IPv6Subnets)) {
		result.Add(subnet.String(), true)
	}
	return result
}

func parsePrefixes(values []string) []netip.Prefix {
	result := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		if prefix, err := netip.ParsePrefix(value); err == nil {
			result = append(result, prefix.Masked())
		}
	}
	return result
}

func collapsePrefixes(prefixes []netip.Prefix) []netip.Prefix {
	if len(prefixes) == 0 {
		return nil
	}
	for {
		// Широкий префикс идёт раньше вложенных с тем же началом.
		sort.Slice(prefixes, func(i, j int) bool {
			if c := prefixes[i].Addr().Compare(prefixes[j].Addr()); c != 0 {
				return c < 0
			}
			return prefixes[i].Bits() < prefixes[j].Bits()
		})
		kept := prefixes[:0:0]
		for _, prefix := range prefixes {
			if n := len(kept); n > 0 && kept[n-1].Bits() <= prefix.Bits() && kept[n-1].Contains(prefix.Addr()) {
				continue
			}
			kept = append(kept, prefix)
		}
		merged := make([]netip.Prefix, 0, len(kept))
		changed := false
		for i := 0; i < len(kept); i++ {
			if i+1 < len(kept) && siblings(kept[i], kept[i+1]) {
				parent, _ := kept[i].Addr().Prefix(kept[i].Bits() - 1)
				merged = append(merged, parent)
				changed = true
				i++
				continue
			}
			merged = append(merged, kept[i])
		}
		prefixes = merged
		if !changed {
			return prefixes
		}
	}
}

// siblings сообщает, что a и b — две половины одного префикса на бит короче.
func siblings(a, b netip.Prefix) bool {
	if a.Bits() != b.Bits() || a.Bits() == 0 {
		return false
	}
	parentA, _ := a.Addr().Prefix(a.Bits() - 1)
	parentB, _ := b.Addr().Prefix(b.Bits() - 1)
	return parentA == parentB && a.Addr() != b.Addr()
}
