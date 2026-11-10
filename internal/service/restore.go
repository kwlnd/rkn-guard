package service

import (
	"fmt"
	"os"

	"github.com/rs/zerolog"
)

// RestoreFirewall запускается при загрузке до UFW: поднимает наборы из
// /etc/ipset.conf и цепочки с переходом из INPUT первым правилом.
// Включённый UFW потом перезапишет содержимое цепочки из before.rules — оно то же.
func RestoreFirewall(logger zerolog.Logger) error {
	cmdSvc := NewCommandService(logger)
	if _, err := os.Stat(IpsetConfigPath); err == nil {
		if err := NewIpsetCommandService(logger, cmdSvc).Restore(IpsetConfigPath); err != nil {
			return fmt.Errorf("не удалось восстановить наборы ipset: %w", err)
		}
	}
	_, logging := os.Stat(RsyslogConfigPath)
	return NewIptablesService(logger, cmdSvc, logging == nil).SetupChainLinked(true)
}
