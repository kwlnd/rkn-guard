package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
	_ "time/tzdata"

	"github.com/spf13/cobra"

	"github.com/Flecksis/rkn-guard/internal/service"
)

func updateCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "update",
		Short: "Скачать списки и обновить наборы (счётчики не сбрасываются)",
		Long: `Скачивает все включённые списки, сжимает пересекающиеся подсети, добавляет
ручные баны и атомарно подменяет наборы ipset. Правила iptables не трогаются.

Недоступный источник не ломает обновление: для него берётся последняя
проверенная копия, а код выхода будет 2.`,
		Args: cobra.NoArgs,
		// Старое меню передавало сюда -u/--managed-lists; молча их принимаем.
		FParseErrWhitelist: cobra.FParseErrWhitelist{UnknownFlags: true},
		RunE: func(cmd *cobra.Command, args []string) error {
			return privileged(func() error {
				networks, warnings, err := rebuildSets(true)
				if err != nil {
					return err
				}
				fmt.Println(okText("✓ списки обновлены: ") + setsSummary(networks))
				return partialIfWarnings(warnings)
			})
		},
	}
}

// sourceRef — номер в выводе sources: b1… для базовых, 1… для дополнительных.
type sourceRef struct {
	base bool
	id   int
}

func parseSourceRef(value string) (sourceRef, error) {
	ref := sourceRef{}
	number := value
	if rest, ok := strings.CutPrefix(strings.ToLower(value), "b"); ok {
		ref.base, number = true, rest
	}
	id, err := strconv.Atoi(number)
	if err != nil || id < 1 {
		return ref, fmt.Errorf("%q: номер списка из rkn-guard sources, например 3 или b1", value)
	}
	ref.id = id
	return ref, nil
}

func sourcesCommand() *cobra.Command {
	var noApply bool
	cmd := &cobra.Command{
		Use:   "sources",
		Short: "Показать и настроить списки подсетей",
		Long: `Базовые списки (b1, b2, …) встроены в rkn-guard; файл /etc/rkn-guard-sources.list,
если он есть, полностью их заменяет. Дополнительные (1, 2, …) добавляете вы.

После изменения наборы сразу пересобираются (отключить: --no-apply).`,
		Example: `  rkn-guard sources
  rkn-guard sources add https://example.org/list.txt
  rkn-guard sources disable b3
  rkn-guard sources remove 2`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return privileged(showSources)
		},
	}
	cmd.PersistentFlags().BoolVar(&noApply, "no-apply", false, "только сохранить настройки, наборы не пересобирать")
	apply := func() error {
		if noApply {
			fmt.Println("Сохранено. Применить: sudo rkn-guard update")
			return nil
		}
		networks, warnings, err := rebuildSets(true)
		if err != nil {
			return fmt.Errorf("настройки сохранены, но наборы не обновлены: %w", err)
		}
		fmt.Println(okText("✓ применено: ") + setsSummary(networks))
		return partialIfWarnings(warnings)
	}

	var disabled bool
	add := &cobra.Command{
		Use:   "add <url>",
		Short: "Добавить список (текст, один IP или CIDR на строку)",
		Long:  "Список скачивается и проверяется до сохранения. Ссылки github.com/…/blob/… переводятся на raw.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return privileged(func() error {
				base, err := loadBase()
				if err != nil {
					return err
				}
				store := sourceStore()
				id, err := store.Add(args[0], base)
				if err != nil {
					return fmt.Errorf("список не добавлен: %w", err)
				}
				if disabled {
					fmt.Printf("Список %d добавлен выключенным. Включить: rkn-guard sources enable %d\n", id, id)
					return nil
				}
				if err := store.Change(id, "enable"); err != nil {
					return err
				}
				fmt.Printf("Список %d добавлен.\n", id)
				return apply()
			})
		},
	}
	add.Flags().BoolVar(&disabled, "disabled", false, "добавить выключенным")

	toggle := func(use, short string, enabled bool) *cobra.Command {
		return &cobra.Command{
			Use:   use + " <номер>...",
			Short: short,
			Args:  cobra.MinimumNArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				return privileged(func() error {
					base, err := loadBase()
					if err != nil {
						return err
					}
					store := sourceStore()
					for _, arg := range args {
						ref, err := parseSourceRef(arg)
						if err != nil {
							return err
						}
						if ref.base {
							err = store.ChangeBase(base, ref.id, enabled)
						} else {
							err = store.Change(ref.id, use)
						}
						if err != nil {
							return err
						}
					}
					if !enabled {
						for _, arg := range args {
							if strings.HasPrefix(strings.ToLower(arg), "b") {
								logPtr().Warn().Msg("базовый список выключен — защита станет слабее")
								break
							}
						}
					}
					return apply()
				})
			},
		}
	}

	remove := &cobra.Command{
		Use:   "remove <номер>...",
		Short: "Удалить дополнительный список",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return privileged(func() error {
				store := sourceStore()
				for _, arg := range args {
					ref, err := parseSourceRef(arg)
					if err != nil {
						return err
					}
					if ref.base {
						return fmt.Errorf("%s: базовый список нельзя удалить, только выключить (sources disable %s)", arg, arg)
					}
					if err := store.Change(ref.id, "remove"); err != nil {
						return err
					}
				}
				return apply()
			})
		},
	}

	cmd.AddCommand(
		&cobra.Command{Use: "list", Short: "Показать списки (то же, что sources без аргументов)", Args: cobra.NoArgs,
			RunE: func(cmd *cobra.Command, args []string) error { return privileged(showSources) }},
		add,
		toggle("enable", "Включить списки", true),
		toggle("disable", "Выключить списки", false),
		remove,
	)
	return cmd
}

func showSources() error {
	base, err := loadBase()
	if err != nil {
		return err
	}
	store := sourceStore()
	baseSources, err := store.BaseSources(base)
	if err != nil {
		return err
	}
	state, err := store.Load()
	if err != nil {
		return err
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "№\tсостояние\tподсетей\tобновлён\turl")
	for _, s := range baseSources {
		sourceRow(w, "b"+strconv.Itoa(s.ID), s, state.Cache[s.URL])
	}
	for _, s := range state.Extra {
		sourceRow(w, strconv.Itoa(s.ID), s, state.Cache[s.URL])
	}
	if err := w.Flush(); err != nil {
		return err
	}
	for _, s := range append(baseSources, state.Extra...) {
		if e := state.Cache[s.URL].LastError; e != "" {
			fmt.Println(warnText("! " + s.URL + ": " + e))
		}
	}
	if len(state.Extra) == 0 {
		fmt.Println(dimText("\nДополнительных списков нет. Добавить: rkn-guard sources add <url>"))
	}
	return nil
}

func sourceRow(w io.Writer, ref string, s service.ExtraSource, cache service.SourceCache) {
	status := dimText("выкл")
	if s.Enabled {
		status = okText("вкл")
	}
	count := "—"
	if len(cache.Networks) > 0 {
		count = strconv.Itoa(len(cache.Networks))
	}
	fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", ref, status, count, shortTime(cache.UpdatedAt), s.URL)
}

func shortTime(value string) string {
	t, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return "—"
	}
	moscow, err := time.LoadLocation("Europe/Moscow")
	if err != nil {
		return t.Format("02.01 15:04 UTC")
	}
	return t.In(moscow).Format("02.01 15:04 МСК")
}

func banCommand() *cobra.Command {
	return &cobra.Command{
		Use:     "ban <ip|cidr>...",
		Short:   "Заблокировать адреса вручную (IPv4 и IPv6)",
		Long:    "Ручные баны хранятся в " + service.BansPath + " и переживают обновления списков.",
		Example: "  rkn-guard ban 203.0.113.7 198.51.100.0/24 2001:db8::1",
		Args:    cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return privileged(func() error {
				added, err := banStore().Add(args)
				if err != nil {
					return err
				}
				if len(added) == 0 {
					fmt.Println("Эти адреса уже заблокированы вручную.")
					return nil
				}
				if _, _, err := rebuildSets(false); err != nil {
					return fmt.Errorf("бан сохранён, но не применён: %w", err)
				}
				fmt.Println(okText("✓ заблокировано: ") + strings.Join(added, ", "))
				return nil
			})
		},
	}
}

func unbanCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "unban <ip|cidr>...",
		Short: "Снять ручной бан",
		Long:  "Снимает только ручные баны. Адрес из списков останется заблокирован, пока его источник включён.",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return privileged(func() error {
				removed, err := banStore().Remove(args)
				if err != nil {
					return err
				}
				if len(removed) == 0 {
					return errors.New("среди ручных банов таких адресов нет (список: rkn-guard bans)")
				}
				if _, _, err := rebuildSets(false); err != nil {
					return fmt.Errorf("бан снят из списка, но наборы не обновлены: %w", err)
				}
				fmt.Println(okText("✓ разблокировано: ") + strings.Join(removed, ", "))
				return nil
			})
		},
	}
}

func bansCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "bans",
		Short: "Показать ручные баны",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireRoot(); err != nil {
				return err
			}
			bans, err := banStore().List()
			if err != nil {
				return err
			}
			if len(bans) == 0 {
				fmt.Println("Ручных банов нет. Добавить: rkn-guard ban <ip>")
			}
			for _, b := range bans {
				fmt.Println(b)
			}
			return nil
		},
	}
}
