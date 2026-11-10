package service

import (
	"bufio"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Flecksis/rkn-guard/internal/domain"
)

const (
	StateDir       = "/var/lib/rkn-guard"
	BansPath       = StateDir + "/bans.list"
	legacyBansPath = "/opt/rkn-guard-manual.list"
)

// BanStore хранит ручные блокировки. Они входят в наборы при каждом обновлении,
// поэтому замена наборов новыми списками их не теряет.
type BanStore struct {
	Path       string
	LegacyPath string
}

// NewBanStore хранит баны в dir; файл старого меню переносится только из стандартного каталога.
func NewBanStore(dir string) *BanStore {
	store := &BanStore{Path: filepath.Join(dir, "bans.list")}
	if store.Path == BansPath {
		store.LegacyPath = legacyBansPath
	}
	return store
}

// NormalizeBan принимает IP или CIDR и возвращает каноническую запись.
func NormalizeBan(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if prefix, err := netip.ParsePrefix(raw); err == nil {
		if prefix.Addr().Zone() != "" || prefix.Addr().Is4In6() || prefix.Bits() == 0 {
			return "", fmt.Errorf("%q: недопустимая подсеть", raw)
		}
		prefix = prefix.Masked()
		if prefix.IsSingleIP() {
			return prefix.Addr().String(), nil
		}
		return prefix.String(), nil
	}
	addr, err := netip.ParseAddr(raw)
	if err != nil || addr.Zone() != "" || addr.Is4In6() {
		return "", fmt.Errorf("%q: это не IP-адрес и не подсеть CIDR", raw)
	}
	return addr.String(), nil
}

// List возвращает ручные блокировки; при первом вызове переносит старый файл меню.
func (b *BanStore) List() ([]string, error) {
	entries, err := readBanFile(b.Path)
	if err == nil {
		return entries, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if b.LegacyPath == "" {
		return nil, nil
	}
	legacy, err := readBanFile(b.LegacyPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	return legacy, err
}

func readBanFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	seen := map[string]bool{}
	var result []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line, _, _ := strings.Cut(scanner.Text(), "#")
		if strings.TrimSpace(line) == "" {
			continue
		}
		// Старое меню записывало что угодно; битые строки пропускаем, а не падаем.
		entry, err := NormalizeBan(line)
		if err != nil || seen[entry] {
			continue
		}
		seen[entry] = true
		result = append(result, entry)
	}
	return result, scanner.Err()
}

func (b *BanStore) save(entries []string) error {
	sort.Strings(entries)
	if err := os.MkdirAll(filepath.Dir(b.Path), 0700); err != nil {
		return err
	}
	data := strings.Join(entries, "\n")
	if data != "" {
		data += "\n"
	}
	if err := atomicWriteFile(b.Path, []byte(data), 0600); err != nil {
		return err
	}
	if b.LegacyPath != "" {
		_ = os.Remove(b.LegacyPath)
	}
	return nil
}

// Add добавляет записи и возвращает те, которых ещё не было.
func (b *BanStore) Add(raw []string) ([]string, error) {
	current, err := b.List()
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, entry := range current {
		seen[entry] = true
	}
	var added []string
	for _, value := range raw {
		entry, err := NormalizeBan(value)
		if err != nil {
			return nil, err
		}
		if !seen[entry] {
			seen[entry] = true
			added = append(added, entry)
		}
	}
	if len(added) == 0 {
		return nil, nil
	}
	return added, b.save(append(current, added...))
}

// Remove убирает записи и возвращает те, что действительно были в списке.
func (b *BanStore) Remove(raw []string) ([]string, error) {
	current, err := b.List()
	if err != nil {
		return nil, err
	}
	drop := map[string]bool{}
	for _, value := range raw {
		entry, err := NormalizeBan(value)
		if err != nil {
			return nil, err
		}
		drop[entry] = true
	}
	var kept, removed []string
	for _, entry := range current {
		if drop[entry] {
			removed = append(removed, entry)
		} else {
			kept = append(kept, entry)
		}
	}
	if len(removed) == 0 {
		return nil, nil
	}
	return removed, b.save(kept)
}

// MergeBans добавляет ручные блокировки к спискам и сжимает результат.
func MergeBans(networks *domain.NetworkList, bans []string) *domain.NetworkList {
	merged := domain.NewNetworkList()
	merged.IPv4Subnets = append(merged.IPv4Subnets, networks.IPv4Subnets...)
	merged.IPv6Subnets = append(merged.IPv6Subnets, networks.IPv6Subnets...)
	for _, entry := range bans {
		prefix, err := netip.ParsePrefix(entry)
		if err != nil {
			addr, addrErr := netip.ParseAddr(entry)
			if addrErr != nil {
				continue
			}
			prefix = netip.PrefixFrom(addr, addr.BitLen())
		}
		merged.Add(prefix.Masked().String(), prefix.Addr().Is6())
	}
	return CollapseNetworks(merged)
}
