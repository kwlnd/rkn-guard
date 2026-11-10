package service

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/rs/zerolog"
)

const (
	chainName = "SCANNERS-BLOCK"
)

// IptablesService управляет правилами iptables и ip6tables.
type IptablesService struct {
	logger        zerolog.Logger
	enableLogging bool
	cmdSvc        *CommandService
	iptablesCmd   *IptablesCommandService
}

// NewIptablesService создаёт сервис управления iptables.
func NewIptablesService(logger zerolog.Logger, cmdSvc *CommandService, enableLogging bool) *IptablesService {
	return &IptablesService{
		logger:        logger,
		enableLogging: enableLogging,
		cmdSvc:        cmdSvc,
		iptablesCmd:   NewIptablesCommandService(logger, cmdSvc),
	}
}

// SetupChain создаёт цепочки и добавляет правила.
func (s *IptablesService) SetupChain() error {
	s.logger.Debug().Msg("Настройка цепочек iptables")

	// Переход из INPUT ставим первым правилом и при активном UFW: другие
	// скрипты часто добавляют в INPUT свои ACCEPT до цепочек UFW, и тогда
	// сканеры на открытых портах не доходили бы до ufw-before-input.
	return s.SetupChainLinked(true)
}

// SetupChainLinked настраивает цепочки; linkToInput добавляет переход из INPUT.
func (s *IptablesService) SetupChainLinked(linkToInput bool) error {

	// Настраиваем IPv4.
	if err := s.setupVersionChain(IPv4, ipsetV4Name, linkToInput); err != nil {
		return fmt.Errorf("failed to setup IPv4 chain: %w", err)
	}

	// Настраиваем IPv6.
	if err := s.setupVersionChain(IPv6, ipsetV6Name, linkToInput); err != nil {
		return fmt.Errorf("failed to setup IPv6 chain: %w", err)
	}

	s.logger.Debug().Msg("Цепочки iptables настроены")
	return nil
}

// setupVersionChain настраивает SCANNERS-BLOCK для выбранной версии IP.
func (s *IptablesService) setupVersionChain(version IPVersion, ipsetName string, linkToInput bool) error {
	s.logger.Debug().Str("version", string(version)).Msg("Настройка цепочки")

	// Проверяем, существует ли цепочка.
	// При повторной установке добавляем недостающие правила, не снимая защиту.
	if !s.iptablesCmd.ChainExists(version, TableFilter, chainName) {
		s.logger.Debug().Str("chain", chainName).Str("version", string(version)).Msg("Создание цепочки")
		if err := s.iptablesCmd.CreateChain(version, TableFilter, chainName); err != nil {
			return fmt.Errorf("failed to create chain: %w", err)
		}
	}

	// Без UFW подключаем нашу цепочку напрямую к INPUT.
	if linkToInput {
		if !s.iptablesCmd.RuleExists(version, TableFilter, string(ChainInput), []string{"-j", chainName}) {
			s.logger.Debug().Str("version", string(version)).Msg("Привязка цепочки к INPUT")
			if err := s.iptablesCmd.LinkChainToInput(version, chainName, 1); err != nil {
				return fmt.Errorf("failed to link chain to INPUT: %w", err)
			}
		}
	}

	// Пропускаем ответы на исходящие соединения через ESTABLISHED,RELATED.
	establishedRule := NewRuleBuilder().
		MatchConntrack("ESTABLISHED", "RELATED").
		Jump(TargetReturn).
		Build()
	if !s.iptablesCmd.RuleExists(version, TableFilter, chainName, establishedRule) {
		s.logger.Debug().Str("version", string(version)).Msg("Добавление правила для установленных соединений")
		if err := s.iptablesCmd.InsertRule(version, TableFilter, chainName, 1, establishedRule); err != nil {
			return fmt.Errorf("failed to add ESTABLISHED rule: %w", err)
		}
	}

	// Если включён журнал, добавляем его правило после ESTABLISHED.
	if s.enableLogging {
		versionLabel := "v4"
		if version == IPv6 {
			versionLabel = "v6"
		}
		logPrefix := fmt.Sprintf("ANTISCAN-%s: ", versionLabel)
		logRule := NewRuleBuilder().
			MatchSet(ipsetName, "src").
			MatchLimit("10/min", "5").
			Jump(TargetLog).
			LogPrefix(logPrefix).
			LogLevel("4").
			Build()
		if !s.iptablesCmd.RuleExists(version, TableFilter, chainName, logRule) {
			s.logger.Debug().Str("version", string(version)).Msg("Добавление правила логирования")
			if err := s.iptablesCmd.InsertRule(version, TableFilter, chainName, 2, logRule); err != nil {
				return fmt.Errorf("failed to add LOG rule: %w", err)
			}
		}
	}

	// Ставим DROP после правил ESTABLISHED и LOG.
	dropRule := NewRuleBuilder().MatchSet(ipsetName, "src").Jump(TargetDrop).Build()
	if !s.iptablesCmd.RuleExists(version, TableFilter, chainName, dropRule) {
		s.logger.Debug().Str("version", string(version)).Msg("Добавление правила блокировки")
		if err := s.iptablesCmd.AppendRule(version, TableFilter, chainName, dropRule); err != nil {
			return fmt.Errorf("failed to add DROP rule: %w", err)
		}
	}

	return nil
}

// Save делает правила постоянными. Активный UFW получает наш блок в before.rules.
// Выключенный UFW rkn-guard не включает: на сервере это закрыло бы все порты,
// кроме разрешённых в UFW. Без UFW правила при загрузке поднимает rkn-guard restore.
func (s *IptablesService) Save() error {
	if s.isUFWActive() {
		s.logger.Info().Msg("UFW активен: правила добавлены и в его before.rules")
		return s.saveWithUFW()
	}
	// Старые установки сохраняли цепочки через netfilter-persistent; держим их файлы актуальными.
	if s.cmdSvc.CommandExists("netfilter-persistent") {
		return s.saveWithNetfilterPersistent()
	}
	return nil
}

// isUFWActive проверяет наличие и состояние UFW.
// removeManagedBlock удаляет наш блок из файла before.rules.
func (s *IptablesService) removeManagedBlock(content, startMarker string) string {
	endMarker := "# END SCANNERS-BLOCK"

	for {
		start := strings.Index(content, startMarker)
		if start == -1 {
			break
		}

		endRel := strings.Index(content[start:], endMarker)
		if endRel == -1 {
			s.logger.Warn().Msg("Managed block end marker not found, skipping removal")
			break
		}

		end := start + endRel + len(endMarker)
		// Убираем переводы строк после блока.
		for end < len(content) && (content[end] == '\n' || content[end] == '\r') {
			end++
		}

		content = content[:start] + content[end:]
	}

	return content
}

func (s *IptablesService) isUFWActive() bool {
	if !s.cmdSvc.CommandExists("ufw") {
		return false
	}

	output, err := s.cmdSvc.RunOutput("ufw", "status")
	if err != nil {
		return false
	}

	return strings.Contains(output, "Status: active")
}

// saveWithUFW сохраняет и применяет правила через UFW.
func (s *IptablesService) saveWithUFW() (result error) {
	status, err := s.cmdSvc.RunOutput("ufw", "status")
	if err != nil {
		return fmt.Errorf("cannot query UFW: %w", err)
	}
	wasActive := strings.Contains(status, "Status: active")
	if !wasActive {
		return fmt.Errorf("UFW не активен; rkn-guard его не включает")
	}

	// UFW сохраняет правила автоматически
	// Нужно только добавить наши правила в before.rules

	beforeRulesV4 := "/etc/ufw/before.rules"
	beforeRulesV6 := "/etc/ufw/before6.rules"

	// Читаем текущие before.rules
	contentV4, err := os.ReadFile(beforeRulesV4)
	if err != nil {
		return fmt.Errorf("failed to read UFW before.rules: %w", err)
	}

	contentV6, err := os.ReadFile(beforeRulesV6)
	if err != nil {
		return fmt.Errorf("failed to read UFW before6.rules: %w", err)
	}
	infoV4, err := os.Stat(beforeRulesV4)
	if err != nil {
		return err
	}
	infoV6, err := os.Stat(beforeRulesV6)
	if err != nil {
		return err
	}
	applyAttempted := false
	applySucceeded := false
	defer func() {
		if result == nil {
			return
		}
		result = errors.Join(result, rollbackUFW(s.cmdSvc, applyAttempted && (wasActive || applySucceeded), func() error {
			return errors.Join(atomicWriteFile(beforeRulesV4, contentV4, infoV4.Mode().Perm()), atomicWriteFile(beforeRulesV6, contentV6, infoV6.Mode().Perm()))
		}))
	}()

	// Проверяем есть ли уже наша цепочка
	markerV4 := "# SCANNERS-BLOCK chain - managed by antiscan"
	markerV6 := "# SCANNERS-BLOCK chain - managed by antiscan"

	// Удаляем старый managed блок если существует (для поддержки обновлений)
	contentV4Str := string(contentV4)
	if strings.Contains(contentV4Str, markerV4) {
		s.logger.Debug().Msg("Обнаружен существующий блок SCANNERS-BLOCK в before.rules, обновляем...")
		contentV4Str = s.removeManagedBlock(contentV4Str, markerV4)
	}

	// Добавляем наши правила в before.rules (внутри существующей секции *filter)
	// Генерируем правила используя RuleBuilder
	establishedRuleV4 := strings.Join(NewRuleBuilder().
		MatchConntrack("ESTABLISHED", "RELATED").
		Jump(TargetReturn).
		Build(), " ")

	logRuleV4 := ""
	if s.enableLogging {
		logRuleV4 = fmt.Sprintf("-A %s %s\n", chainName, strings.Join(NewRuleBuilder().
			MatchSet(ipsetV4Name, "src").
			MatchLimit("10/min", "5").
			Jump(TargetLog).
			LogPrefix("\"ANTISCAN-v4: \"").
			LogLevel("4").
			Build(), " "))
	}

	dropRuleV4 := strings.Join(NewRuleBuilder().
		MatchSet(ipsetV4Name, "src").
		Jump(TargetDrop).
		Build(), " ")

	rulesV4 := fmt.Sprintf(`
# SCANNERS-BLOCK chain - managed by antiscan
# Этот раздел создаёт rkn-guard. Не редактируйте его вручную.
:%s - [0:0]
-A ufw-before-input -j %s
-A %s %s
%s
-A %s %s
# END SCANNERS-BLOCK

`, chainName, chainName, chainName, establishedRuleV4, logRuleV4, chainName, dropRuleV4)

	// Сохраняем переход перед остальными правилами таблицы filter.
	newContent, err := insertUFWBlock(contentV4Str, rulesV4, "ufw-before-input")
	if err != nil {
		return fmt.Errorf("before.rules: %w", err)
	}
	if err := atomicWriteFile(beforeRulesV4, []byte(newContent), infoV4.Mode().Perm()); err != nil {
		return fmt.Errorf("failed to write UFW rules: %w", err)
	}
	s.logger.Debug().Msg("Обновлён UFW before.rules для IPv4")

	if contentV6 != nil {
		// Удаляем старый managed блок если существует (для поддержки обновлений)
		contentV6Str := string(contentV6)
		if strings.Contains(contentV6Str, markerV6) {
			s.logger.Debug().Msg("Обнаружен существующий блок SCANNERS-BLOCK в before6.rules, обновляем...")
			contentV6Str = s.removeManagedBlock(contentV6Str, markerV6)
		}

		// Генерируем правила используя RuleBuilder
		establishedRuleV6 := strings.Join(NewRuleBuilder().
			MatchConntrack("ESTABLISHED", "RELATED").
			Jump(TargetReturn).
			Build(), " ")

		logRuleV6 := ""
		if s.enableLogging {
			logRuleV6 = fmt.Sprintf("-A %s %s\n", chainName, strings.Join(NewRuleBuilder().
				MatchSet(ipsetV6Name, "src").
				MatchLimit("10/min", "5").
				Jump(TargetLog).
				LogPrefix("\"ANTISCAN-v6: \"").
				LogLevel("4").
				Build(), " "))
		}

		dropRuleV6 := strings.Join(NewRuleBuilder().
			MatchSet(ipsetV6Name, "src").
			Jump(TargetDrop).
			Build(), " ")

		rulesV6 := fmt.Sprintf(`
# SCANNERS-BLOCK chain - managed by antiscan
# Этот раздел создаёт rkn-guard. Не редактируйте его вручную.
:%s - [0:0]
-A ufw6-before-input -j %s
-A %s %s
%s
-A %s %s
# END SCANNERS-BLOCK

`, chainName, chainName, chainName, establishedRuleV6, logRuleV6, chainName, dropRuleV6)

		newContent, err := insertUFWBlock(contentV6Str, rulesV6, "ufw6-before-input")
		if err != nil {
			return fmt.Errorf("before6.rules: %w", err)
		}
		if err := atomicWriteFile(beforeRulesV6, []byte(newContent), infoV6.Mode().Perm()); err != nil {
			return fmt.Errorf("failed to write UFW IPv6 rules: %w", err)
		}
	}

	// Применяем правила через reload, не отключая работающий UFW.
	currentV4, err := os.ReadFile(beforeRulesV4)
	if err != nil {
		return err
	}
	currentV6, err := os.ReadFile(beforeRulesV6)
	if err != nil {
		return err
	}
	// Повторная установка с теми же правилами не сбрасывает счётчики UFW.
	if wasActive && string(currentV4) == string(contentV4) && string(currentV6) == string(contentV6) && verifyUFWJumps(s.cmdSvc) == nil {
		return nil
	}
	applyAttempted = true
	if err := applyUFW(s.cmdSvc, wasActive); err != nil {
		return err
	}
	applySucceeded = true
	if err := verifyUFWJumps(s.cmdSvc); err != nil {
		return err // Отложенный откат восстановит файлы и перезагрузит активный UFW.
	}

	// Порядок уже записан в before-файлах, отдельный сервис для перестановки не нужен.

	s.logger.Debug().Msg("Правила iptables интегрированы с UFW")
	return nil
}

// saveWithNetfilterPersistent сохраняет правила через netfilter-persistent.
func (s *IptablesService) saveWithNetfilterPersistent() error {
	// Создаем директорию если не существует
	if err := os.MkdirAll("/etc/iptables", 0755); err != nil {
		return fmt.Errorf("failed to create /etc/iptables: %w", err)
	}

	if err := s.iptablesCmd.Save(IPv4, "/etc/iptables/rules.v4"); err != nil {
		return fmt.Errorf("failed to save iptables: %w", err)
	}
	s.logger.Debug().Msg("Правила IPv4 сохранены в /etc/iptables/rules.v4")

	if err := s.iptablesCmd.Save(IPv6, "/etc/iptables/rules.v6"); err != nil {
		return fmt.Errorf("failed to save ip6tables: %w", err)
	}
	s.logger.Debug().Msg("Правила IPv6 сохранены в /etc/iptables/rules.v6")

	// Применяем через netfilter-persistent
	if err := s.cmdSvc.Run("netfilter-persistent", "save"); err != nil {
		s.logger.Warn().Err(err).Msg("netfilter-persistent save не сработал")
	}

	return nil
}
