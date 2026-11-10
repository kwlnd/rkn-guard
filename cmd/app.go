package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/mattn/go-isatty"
	"github.com/rs/zerolog"

	"github.com/Flecksis/rkn-guard/internal/domain"
	"github.com/Flecksis/rkn-guard/internal/logger"
	"github.com/Flecksis/rkn-guard/internal/service"
)

// partialError — команда выполнена, но часть источников не ответила. Код выхода 2.
type partialError struct{ msg string }

func (e *partialError) Error() string { return e.msg }

func log() zerolog.Logger { return logger.Global().Logger }

func logPtr() *zerolog.Logger {
	l := log()
	return &l
}

func paint(f *os.File, code, text string) string {
	if !logger.ColorEnabled(f) {
		return text
	}
	return "\033[" + code + "m" + text + "\033[0m"
}

func okText(s string) string    { return paint(os.Stdout, "32", s) }
func dimText(s string) string   { return paint(os.Stdout, "90", s) }
func boldText(s string) string  { return paint(os.Stdout, "1", s) }
func warnText(s string) string  { return paint(os.Stderr, "33", s) }
func errorText(s string) string { return paint(os.Stderr, "31", s) }

func requireRoot() error {
	if os.Geteuid() != 0 {
		return errors.New("нужны права root: запустите через sudo")
	}
	return nil
}

// privileged проверяет root и держит общую блокировку на время fn,
// чтобы таймер обновления и ручные команды не меняли наборы одновременно.
func privileged(fn func() error) error {
	if err := requireRoot(); err != nil {
		return err
	}
	lock, err := service.AcquireLock()
	if err != nil {
		return errors.New("уже идёт другая операция rkn-guard; повторите позже")
	}
	defer lock.Close()
	return fn()
}

func sourceStore() *service.SourceStore {
	return &service.SourceStore{Path: filepath.Join(stateDir, "sources.json"), Downloader: service.NewDownloader(log())}
}

func banStore() *service.BanStore { return service.NewBanStore(stateDir) }

func loadBase() ([]string, error) { return service.LoadBaseSources(baseSources) }

// rebuildSets собирает списки и ручные баны и атомарно подменяет наборы ipset.
// download=false берёт сохранённые копии списков — так баны применяются без сети.
func rebuildSets(download bool) (*domain.NetworkList, []string, error) {
	base, err := loadBase()
	if err != nil {
		return nil, nil, err
	}
	store := sourceStore()
	var networks *domain.NetworkList
	var warnings []string
	if download {
		networks, warnings, err = store.Download(base)
		for _, w := range warnings {
			logPtr().Warn().Msg(w)
		}
		if errors.Is(err, service.ErrNoSourceData) {
			return nil, warnings, errors.New("ни один список не скачался и сохранённых копий нет; действующие правила не тронуты")
		}
	} else {
		networks, err = store.Cached(base)
	}
	if err != nil {
		return nil, warnings, err
	}
	bans, err := banStore().List()
	if err != nil {
		return nil, warnings, fmt.Errorf("не удалось прочитать ручные баны: %w", err)
	}
	networks = service.MergeBans(networks, bans)
	ipsets := service.NewIpsetService(log(), service.NewCommandService(log()))
	if networks.TotalCount() == 0 {
		logPtr().Warn().Msg("все источники выключены и ручных банов нет — наборы очищены")
		err = ipsets.Clear(service.IpsetConfigPath)
	} else {
		err = ipsets.Replace(networks, service.IpsetConfigPath)
	}
	if err != nil {
		return nil, warnings, fmt.Errorf("не удалось обновить наборы ipset: %w", err)
	}
	return networks, warnings, nil
}

func setsSummary(n *domain.NetworkList) string {
	return fmt.Sprintf("%d IPv4 · %d IPv6", n.IPv4Count(), n.IPv6Count())
}

func partialIfWarnings(warnings []string) error {
	if len(warnings) == 0 {
		return nil
	}
	return &partialError{fmt.Sprintf("часть источников недоступна (%d) — для них взяты последние сохранённые копии, подробности выше", len(warnings))}
}

// confirm спрашивает да/нет. Без терминала отвечает «нет»: нужен явный --yes.
func confirm(question string) bool {
	if !isatty.IsTerminal(os.Stdin.Fd()) {
		return false
	}
	fmt.Fprintf(os.Stderr, "%s [y/N]: ", question)
	answer, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return false
	}
	answer = strings.ToLower(strings.TrimSpace(answer))
	return answer == "y" || answer == "yes" || answer == "д" || answer == "да"
}
