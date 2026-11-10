package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/Flecksis/rkn-guard/internal/service"
)

func scheduleCommand() *cobra.Command {
	var local bool
	cmd := &cobra.Command{
		Use:   "schedule",
		Short: "Показать или задать автообновление списков",
		Example: `  rkn-guard schedule                     текущее расписание
  rkn-guard schedule daily 06:00,18:30   по Москве
  rkn-guard schedule daily 6 --local     по времени сервера
  rkn-guard schedule every 6             каждые 6 часов
  rkn-guard schedule off`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireRoot(); err != nil {
				return err
			}
			s, err := service.LoadSchedule()
			if err != nil {
				return err
			}
			fmt.Println("Автообновление:", scheduleState(s))
			return nil
		},
	}
	apply := func(s service.Schedule) error {
		return privileged(func() error {
			if err := service.NewScheduleService(log(), service.BinaryPath).Apply(s); err != nil {
				return fmt.Errorf("расписание не применено, прежнее восстановлено: %w", err)
			}
			fmt.Println(okText("✓ автообновление: ") + s.String())
			return nil
		})
	}
	daily := &cobra.Command{
		Use:   "daily <ЧЧ:ММ[,ЧЧ:ММ...]>",
		Short: "Ежедневно в заданное время (по Москве, с --local — по времени сервера)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			times, err := service.ParseTimes(args[0])
			if err != nil {
				return err
			}
			mode := service.ScheduleMSK
			if local {
				mode = service.ScheduleLocal
			}
			return apply(service.Schedule{Mode: mode, Times: times})
		},
	}
	daily.Flags().BoolVar(&local, "local", false, "время сервера вместо московского")
	cmd.AddCommand(daily,
		&cobra.Command{
			Use:   "every <часов>",
			Short: "Каждые N часов (1–168)",
			Args:  cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				hours, err := service.ParseInterval(args[0])
				if err != nil {
					return err
				}
				return apply(service.Schedule{Mode: service.ScheduleInterval, Hours: hours})
			},
		},
		&cobra.Command{
			Use:   "off",
			Short: "Выключить автообновление",
			Args:  cobra.NoArgs,
			RunE: func(cmd *cobra.Command, args []string) error {
				return apply(service.Schedule{Mode: service.ScheduleOff})
			},
		},
	)
	return cmd
}

func statsCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "stats",
		Short: "Топ адресов из журнала атак (с ASN и именем сети)",
		Long: `Собирает новые события из журналов и печатает адреса по убыванию числа событий.
Журнал ограничен 10 записями в минуту, так что это выборка, а не все отброшенные
пакеты; полный счётчик — в rkn-guard status.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireRoot(); err != nil {
				return err
			}
			if err := service.NewLoggingService(log()).CheckHealth(); err != nil {
				return fmt.Errorf("сбор статистики не работает (%w); сохранённые данные не удалены, починить: sudo rkn-guard install", err)
			}
			process := exec.Command("python3", "-c", service.AggregateLogsScriptTemplate, "--display")
			process.Stdout, process.Stderr = os.Stdout, os.Stderr
			return process.Run()
		},
	}
}

func logsCommand() *cobra.Command {
	var ipv6, follow bool
	var lines int
	cmd := &cobra.Command{
		Use:     "logs",
		Short:   "Журнал заблокированных подключений",
		Example: "  rkn-guard logs -f\n  rkn-guard logs -6 -n 200",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			path := service.IPv4LogPath
			if ipv6 {
				path = service.IPv6LogPath
			}
			if _, err := os.Stat(path); err != nil {
				return fmt.Errorf("журнала %s нет — статистика не настроена (sudo rkn-guard install)", path)
			}
			argv := []string{"-n", strconv.Itoa(lines)}
			if follow {
				argv = append(argv, "-F")
			}
			tail := exec.Command("tail", append(argv, path)...)
			tail.Stdout, tail.Stderr = os.Stdout, os.Stderr
			if err := tail.Run(); err != nil && !follow {
				return err
			}
			return nil
		},
	}
	cmd.Flags().BoolVarP(&ipv6, "ipv6", "6", false, "журнал IPv6 вместо IPv4")
	cmd.Flags().BoolVarP(&follow, "follow", "f", false, "следить за новыми записями")
	cmd.Flags().IntVarP(&lines, "lines", "n", 50, "сколько последних строк показать")
	return cmd
}

// newerVersion сравнивает версии вида v1.2.3; нечисловые сборки считаются старыми.
func newerVersion(latest, current string) bool {
	parse := func(v string) []int {
		parts := strings.Split(strings.TrimPrefix(v, "v"), ".")
		if len(parts) != 3 {
			return nil
		}
		result := make([]int, 3)
		for i, p := range parts {
			n, err := strconv.Atoi(p)
			if err != nil {
				return nil
			}
			result[i] = n
		}
		return result
	}
	l, c := parse(latest), parse(current)
	if l == nil {
		return false
	}
	if c == nil {
		return true
	}
	for i := range l {
		if l[i] != c[i] {
			return l[i] > c[i]
		}
	}
	return false
}

func upgradeCommand() *cobra.Command {
	var check, force bool
	cmd := &cobra.Command{
		Use:   "upgrade",
		Short: "Обновить сам rkn-guard до последнего релиза",
		Long: `Скачивает бинарник последнего релиза ` + repo + `, сверяет sha256 с checksums.txt
и заменяет установленный. Правила, наборы и счётчики не сбрасываются.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			release, err := service.LatestRelease(context.Background(), repo)
			if err != nil {
				return err
			}
			if !force && !newerVersion(release.Tag, version) {
				fmt.Printf("Установлена %s, последний релиз %s — обновлять нечего.\n", version, release.Tag)
				return nil
			}
			if check {
				fmt.Printf("Доступно обновление: %s → %s. Поставить: sudo rkn-guard upgrade\n", version, release.Tag)
				return nil
			}
			err = privileged(func() error {
				logPtr().Info().Msgf("скачиваю %s", release.Tag)
				return service.InstallRelease(context.Background(), release, service.BinaryPath)
			})
			if err != nil {
				return err
			}
			// Доустановку делает уже новый бинарник: он знает свои юниты и шаблоны.
			// Блокировка к этому моменту отпущена, иначе он бы её не взял.
			post := exec.Command(service.BinaryPath, "setup-logging")
			post.Stdout, post.Stderr = os.Stdout, os.Stderr
			if err := post.Run(); err != nil {
				return fmt.Errorf("бинарник обновлён до %s, но доустановка не прошла: %w; повторите sudo rkn-guard install", release.Tag, err)
			}
			fmt.Println(okText("✓ rkn-guard обновлён: ") + version + " → " + release.Tag)
			return nil
		},
	}
	cmd.Flags().BoolVar(&check, "check", false, "только проверить, есть ли обновление")
	cmd.Flags().BoolVar(&force, "force", false, "переустановить, даже если версия та же")
	return cmd
}

func versionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Версия и источник сборки",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("rkn-guard %s (ветка %s, релизы: github.com/%s)\n", version, branch, repo)
		},
	}
}
