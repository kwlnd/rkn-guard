package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/Flecksis/rkn-guard/internal/logger"
	"github.com/Flecksis/rkn-guard/internal/service"
)

// Задаются при сборке через -ldflags.
var (
	version = "dev"
	branch  = "unknown"
	repo    = "kwlnd/rkn-guard" // откуда upgrade берёт релизы
)

var (
	verbose     bool
	stateDir    = service.StateDir
	baseSources = service.BaseSourcesOverridePath
)

func newRootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:   "rkn-guard",
		Short: "Блокировка сканеров РКН и госсетей через ipset/iptables",
		Long: `rkn-guard скачивает списки подсетей сканеров, держит их в ipset и
отбрасывает входящий трафик с этих адресов до того, как он дойдёт до сервисов.

Начало работы:
  sudo rkn-guard install     поставить защиту и автообновление
  sudo rkn-guard status      что сейчас работает`,
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			logger.SetGlobalLogger(logger.New(verbose))
		},
	}
	root.SetVersionTemplate("rkn-guard {{.Version}}\n")
	root.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "подробный вывод: системные команды и отладка")
	// Скрытые флаги нужны тестам: состояние и базовые списки во временном каталоге.
	root.PersistentFlags().StringVar(&stateDir, "state-dir", service.StateDir, "каталог настроек списков и ручных банов")
	root.PersistentFlags().StringVar(&baseSources, "base-sources", service.BaseSourcesOverridePath, "файл, заменяющий встроенные базовые списки")
	_ = root.PersistentFlags().MarkHidden("state-dir")
	_ = root.PersistentFlags().MarkHidden("base-sources")

	root.AddGroup(
		&cobra.Group{ID: "setup", Title: "Установка:"},
		&cobra.Group{ID: "lists", Title: "Списки и блокировки:"},
		&cobra.Group{ID: "info", Title: "Состояние:"},
	)
	add := func(group string, commands ...*cobra.Command) {
		for _, c := range commands {
			c.GroupID = group
			root.AddCommand(c)
		}
	}
	add("setup", installCommand(), uninstallCommand(), upgradeCommand(), scheduleCommand())
	add("lists", updateCommand(), sourcesCommand(), banCommand(), unbanCommand(), bansCommand())
	add("info", statusCommand(), statsCommand(), logsCommand(), versionCommand())
	root.AddCommand(hiddenCommands()...)
	root.SetHelpCommandGroupID("info")
	root.SetCompletionCommandGroupID("info")
	localize(root)
	return root
}

func main() {
	logger.SetGlobalLogger(logger.New(false))
	err := newRootCommand().Execute()
	if err == nil {
		return
	}
	var partial *partialError
	if errors.As(err, &partial) {
		fmt.Fprintln(os.Stderr, warnText(partial.Error()))
		os.Exit(2)
	}
	fmt.Fprintln(os.Stderr, errorText("ошибка: "+err.Error()))
	os.Exit(1)
}
