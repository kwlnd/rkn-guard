package service

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/rs/zerolog"
)

const ufwConfigPath = "/etc/ufw/ufw.conf"

// UFWEnabledAtBoot читает ENABLED из ufw.conf: при загрузке ufw status ещё неточен.
func UFWEnabledAtBoot() bool {
	f, err := os.Open(ufwConfigPath)
	if err != nil {
		return false
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if value, ok := strings.CutPrefix(line, "ENABLED="); ok {
			return strings.Trim(value, `"'`) == "yes"
		}
	}
	return false
}

// RestoreFirewall запускается при загрузке до UFW: поднимает наборы из
// /etc/ipset.conf и, если UFW выключен, цепочки с переходом из INPUT.
// При включённом UFW цепочку заполняет сам UFW из before.rules.
func RestoreFirewall(logger zerolog.Logger) error {
	cmdSvc := NewCommandService(logger)
	if _, err := os.Stat(IpsetConfigPath); err == nil {
		if err := NewIpsetCommandService(logger, cmdSvc).Restore(IpsetConfigPath); err != nil {
			return fmt.Errorf("не удалось восстановить наборы ipset: %w", err)
		}
	}
	if UFWEnabledAtBoot() {
		for _, binary := range []string{"iptables", "ip6tables"} {
			_ = cmdSvc.RunQuiet(binary, "-N", chainName)
		}
		return nil
	}
	_, logging := os.Stat(RsyslogConfigPath)
	return NewIptablesService(logger, cmdSvc, logging == nil).SetupChainLinked(true)
}
