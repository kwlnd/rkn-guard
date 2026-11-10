package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/Flecksis/rkn-guard/internal/service"
)

func installCommand() *cobra.Command {
	var noLogging, noSchedule bool
	cmd := &cobra.Command{
		Use:   "install",
		Short: "Поставить или переустановить защиту",
		Long: `Ставит бинарник в /usr/local/bin (и команду rkn), зависимости, скачивает списки,
создаёт цепочку SCANNERS-BLOCK и делает правила постоянными.

Если UFW активен, правила встраиваются в его before.rules. Выключенный UFW
rkn-guard не включает: цепочка подключается к INPUT напрямую.

Повторный запуск безопасен: счётчики и статистика сохраняются, прежнее
расписание обновлений не меняется.`,
		Example: "  sudo rkn-guard install\n  sudo rkn-guard install --no-schedule",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return privileged(func() error { return runInstall(!noLogging, !noSchedule) })
		},
	}
	cmd.Flags().BoolVar(&noLogging, "no-logging", false, "не настраивать журнал и статистику атак")
	cmd.Flags().BoolVar(&noSchedule, "no-schedule", false, "не включать ежедневное автообновление списков")
	return cmd
}

func runInstall(logging, schedule bool) error {
	l := log()
	if copied, err := service.CopySelf(service.BinaryPath); err != nil {
		return fmt.Errorf("не удалось установить бинарник в %s: %w", service.BinaryPath, err)
	} else if copied {
		l.Info().Msgf("бинарник установлен в %s", service.BinaryPath)
	}
	if err := service.LinkShortCommand(); err != nil {
		l.Warn().Err(err).Msg("не удалось создать команду rkn")
	}
	if err := service.RemoveLegacyManager(); err != nil {
		l.Warn().Err(err).Msg("не удалось удалить старое баш-меню")
	}

	l.Info().Msg("проверяю зависимости")
	if err := service.NewInstallerService(l).EnsureDependencies(); err != nil {
		return err
	}

	l.Info().Msg("скачиваю списки")
	networks, warnings, err := rebuildSets(true)
	if err != nil {
		return err
	}
	l.Info().Msgf("в наборах: %s", setsSummary(networks))

	cmdSvc := service.NewCommandService(l)
	iptables := service.NewIptablesService(l, cmdSvc, logging)
	if err := iptables.SetupChain(); err != nil {
		return fmt.Errorf("не удалось настроить iptables: %w", err)
	}
	if err := service.NewIpsetService(l, cmdSvc).CreateRestoreService(); err != nil {
		return fmt.Errorf("не удалось настроить восстановление при загрузке: %w", err)
	}
	if err := iptables.Save(); err != nil {
		return fmt.Errorf("правила применены, но не сохранены: %w", err)
	}
	if logging {
		l.Info().Msg("настраиваю журнал и статистику")
		if err := service.NewLoggingService(l).Refresh(); err != nil {
			return fmt.Errorf("защита работает, но статистика не настроена: %w; повторите install", err)
		}
	}

	if err := installSchedule(schedule); err != nil {
		return fmt.Errorf("защита работает, но автообновление не настроено: %w", err)
	}

	fmt.Println(okText("✓ rkn-guard установлен.") + " Проверить: " + boldText("sudo rkn-guard status"))
	return partialIfWarnings(warnings)
}

// installSchedule не трогает уже выбранное расписание, только переводит старый юнит на новый бинарник.
func installSchedule(enable bool) error {
	schedules := service.NewScheduleService(log(), service.BinaryPath)
	current, err := service.LoadSchedule()
	if err != nil {
		logPtr().Warn().Err(err).Msg("расписание повреждено; задайте его заново: rkn-guard schedule")
		return nil
	}
	_, statErr := os.Stat(service.ScheduleConfigPath)
	if current.Mode != service.ScheduleOff || !enable || statErr == nil {
		return schedules.RewriteService()
	}
	next := service.Schedule{Mode: service.ScheduleLocal, Times: []string{"06:00"}}
	if err := schedules.Apply(next); err != nil {
		return err
	}
	logPtr().Info().Msgf("автообновление: %s (изменить: rkn-guard schedule)", next)
	return nil
}

func uninstallCommand() *cobra.Command {
	var yes, purge bool
	cmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Удалить правила, службы и сам rkn-guard",
		Long: `Убирает цепочки и наборы, блок в правилах UFW, службы и таймеры, команды
rkn и rkn-guard. Журналы, статистика, ручные баны и настройки списков
остаются, пока не указан --purge.`,
		Example: "  sudo rkn-guard uninstall\n  sudo rkn-guard uninstall --yes --purge",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return privileged(func() error {
				if !yes && !confirm("Удалить rkn-guard и снять защиту?") {
					return errors.New("отменено (без терминала подтвердите флагом --yes)")
				}
				return runUninstall(purge)
			})
		},
	}
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "не спрашивать подтверждение")
	cmd.Flags().BoolVar(&purge, "purge", false, "удалить также журналы, статистику, баны и настройки списков")
	return cmd
}

func runUninstall(purge bool) error {
	l := log()
	if err := service.NewScheduleService(l, service.BinaryPath).Apply(service.Schedule{Mode: service.ScheduleOff}); err != nil {
		l.Debug().Err(err).Msg("schedule removal")
	}
	cmdSvc := service.NewCommandService(l)
	if err := service.NewUninstallerService(l, cmdSvc).Uninstall(purge); err != nil {
		return err
	}
	for _, step := range []func() error{service.RemoveShortCommand, service.RemoveLegacyManager} {
		if err := step(); err != nil {
			l.Warn().Err(err).Msg("не удалось удалить файл")
		}
	}
	if purge {
		if err := os.RemoveAll("/var/lib/rkn-guard"); err != nil {
			l.Warn().Err(err).Msg("не удалось удалить /var/lib/rkn-guard")
		}
	}
	if err := os.Remove(service.BinaryPath); err != nil && !os.IsNotExist(err) {
		l.Warn().Err(err).Msg("не удалось удалить бинарник")
	}
	if purge {
		fmt.Println(okText("✓ rkn-guard удалён вместе с данными."))
	} else {
		fmt.Println(okText("✓ rkn-guard удалён.") + dimText(" Журналы и настройки остались; полностью: uninstall --purge"))
	}
	return nil
}

// hiddenCommands нужны старым установкам и юнитам systemd; в справке их нет.
func hiddenCommands() []*cobra.Command {
	ignoreOldFlags := cobra.FParseErrWhitelist{UnknownFlags: true}
	return []*cobra.Command{
		{
			Use:                "full",
			Short:              "старое имя install",
			Hidden:             true,
			FParseErrWhitelist: ignoreOldFlags,
			RunE: func(cmd *cobra.Command, args []string) error {
				return privileged(func() error { return runInstall(true, false) })
			},
		},
		{
			Use:    "setup-logging",
			Short:  "доустановка после upgrade: сборщик статистики, юниты, команда rkn",
			Hidden: true,
			RunE: func(cmd *cobra.Command, args []string) error {
				return privileged(postUpgrade)
			},
		},
		{
			Use:    "restore",
			Short:  "поднять наборы и цепочки при загрузке (вызывает systemd)",
			Hidden: true,
			RunE: func(cmd *cobra.Command, args []string) error {
				if err := requireRoot(); err != nil {
					return err
				}
				return service.RestoreFirewall(log())
			},
		},
		{
			Use:    "build-info",
			Hidden: true,
			Run: func(cmd *cobra.Command, args []string) {
				fmt.Printf("%s\n%s\n", version, branch)
			},
		},
	}
}

// postUpgrade переводит установку на текущий бинарник, не трогая правила и счётчики.
func postUpgrade() error {
	l := log()
	cmdSvc := service.NewCommandService(l)
	var errs []error
	if _, err := os.Stat(service.RsyslogConfigPath); err == nil {
		errs = append(errs, service.NewLoggingService(l).Refresh())
	}
	if _, err := os.Stat(service.IpsetRestoreServicePath); err == nil {
		errs = append(errs, service.NewIpsetService(l, cmdSvc).CreateRestoreService())
	}
	errs = append(errs,
		service.NewScheduleService(l, service.BinaryPath).RewriteService(),
		service.LinkShortCommand(),
		service.RemoveLegacyManager(),
	)
	return errors.Join(errs...)
}
