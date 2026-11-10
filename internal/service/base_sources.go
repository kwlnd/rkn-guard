package service

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// BaseSourcesOverridePath целиком заменяет встроенные базовые списки, если существует.
// Формат: один URL на строку, # — комментарий.
const BaseSourcesOverridePath = "/etc/rkn-guard-sources.list"

// DefaultBaseSources — встроенные базовые списки подсетей.
var DefaultBaseSources = []string{
	"https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/main/public/government_networks.list",
	"https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/main/public/antiscanner.list",
	"https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/main/public/skipa.list",
	"https://raw.githubusercontent.com/C24Be/AS_Network_List/main/blacklists/blacklist.txt",
	"https://raw.githubusercontent.com/tread-lightly/CyberOK_Skipa_ips/main/lists/skipa_cidr.txt",
	// Коммерческие сканеры интернета с собственными диапазонами: их базы
	// используют, чтобы находить серверы. Облачные /32 (BinaryEdge, Stretchoid)
	// не берём: адреса быстро меняют владельцев.
	"https://raw.githubusercontent.com/OpenFilters/internet-scanners/main/cidr/censys_v4.txt",
	"https://raw.githubusercontent.com/OpenFilters/internet-scanners/main/cidr/censys_v6.txt",
	"https://raw.githubusercontent.com/OpenFilters/internet-scanners/main/cidr/shodan_v4.txt",
	"https://raw.githubusercontent.com/OpenFilters/internet-scanners/main/cidr/shodan_v6.txt",
	"https://raw.githubusercontent.com/OpenFilters/internet-scanners/main/cidr/shadowserver_v4.txt",
	"https://raw.githubusercontent.com/OpenFilters/internet-scanners/main/cidr/shadowserver_v6.txt",
	"https://raw.githubusercontent.com/OpenFilters/internet-scanners/main/cidr/onyphe_v4.txt",
}

// LoadBaseSources возвращает базовые списки с учётом файла переопределения.
func LoadBaseSources(path string) ([]string, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return append([]string(nil), DefaultBaseSources...), nil
	}
	if err != nil {
		return nil, fmt.Errorf("не удалось прочитать %s: %w", path, err)
	}
	defer f.Close()
	var result []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line, _, _ := strings.Cut(scanner.Text(), "#")
		if line = strings.TrimSpace(line); line != "" {
			result = append(result, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("не удалось прочитать %s: %w", path, err)
	}
	return result, nil
}
