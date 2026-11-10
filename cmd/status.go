package main

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/Flecksis/rkn-guard/internal/service"
)

func statusCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Что сейчас работает: наборы, правила, счётчики, расписание",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireRoot(); err != nil {
				return err
			}
			return showStatus()
		},
	}
}

// setEntries читает число записей из заголовка ipset list -t.
func setEntries(name string) (int, bool) {
	out, err := exec.Command("ipset", "list", "-t", name).Output()
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(out), "\n") {
		if value, ok := strings.CutPrefix(line, "Number of entries:"); ok {
			n, _ := strconv.Atoi(strings.TrimSpace(value))
			return n, true
		}
	}
	return 0, true
}

// droppedPackets суммирует счётчики правил DROP в цепочке SCANNERS-BLOCK.
// Правило LOG ограничено 10 записями в минуту, поэтому считать по нему нельзя.
func droppedPackets(binary string) (uint64, bool) {
	out, err := exec.Command(binary, "-w", "-nvxL", "SCANNERS-BLOCK").Output()
	if err != nil {
		return 0, false
	}
	var total uint64
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 2 && fields[2] == "DROP" {
			n, _ := strconv.ParseUint(fields[0], 10, 64)
			total += n
		}
	}
	return total, true
}

func linkedVia(binary string) string {
	if exec.Command(binary, "-w", "-C", "INPUT", "-j", "SCANNERS-BLOCK").Run() == nil {
		return "INPUT"
	}
	chain := "ufw-before-input"
	if binary == "ip6tables" {
		chain = "ufw6-before-input"
	}
	if exec.Command(binary, "-w", "-C", chain, "-j", "SCANNERS-BLOCK").Run() == nil {
		return "UFW"
	}
	return ""
}

func showStatus() error {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	row := func(name, value string) { fmt.Fprintf(w, "%s\t%s\n", name, value) }

	row("Версия", version)

	v4, ok4 := setEntries("SCANNERS-BLOCK-V4")
	v6, ok6 := setEntries("SCANNERS-BLOCK-V6")
	via4, via6 := linkedVia("iptables"), linkedVia("ip6tables")
	switch {
	case !ok4 && !ok6:
		row("Защита", warnText("не установлена")+" — sudo rkn-guard install")
	case via4 == "" || via6 == "":
		row("Защита", warnText("наборы есть, но цепочка не подключена")+" — sudo rkn-guard install")
	default:
		row("Защита", okText("работает")+dimText(" (через "+via4+")"))
	}

	sets := fmt.Sprintf("%d IPv4 · %d IPv6", v4, v6)
	if info, err := os.Stat(service.IpsetConfigPath); err == nil {
		sets += dimText(" · обновлены " + info.ModTime().In(moscow()).Format("02.01.2006 15:04") + " МСК")
	}
	row("Подсетей", sets)

	d4, _ := droppedPackets("iptables")
	d6, _ := droppedPackets("ip6tables")
	row("Отброшено", fmt.Sprintf("%d пакетов", d4+d6)+dimText(" (с последней загрузки правил)"))

	if bans, err := banStore().List(); err == nil {
		row("Ручные баны", strconv.Itoa(len(bans)))
	}

	if base, err := loadBase(); err == nil {
		store := sourceStore()
		if baseSources, err := store.BaseSources(base); err == nil {
			if state, err := store.Load(); err == nil {
				on := 0
				for _, s := range baseSources {
					if s.Enabled {
						on++
					}
				}
				extraOn := 0
				for _, s := range state.Extra {
					if s.Enabled {
						extraOn++
					}
				}
				row("Списки", fmt.Sprintf("базовых %d/%d · доп. %d/%d", on, len(baseSources), extraOn, len(state.Extra))+dimText(" (вкл/всего)"))
			}
		}
	}

	schedule, err := service.LoadSchedule()
	if err != nil {
		row("Автообновление", warnText("настройки повреждены")+" — rkn-guard schedule")
	} else {
		row("Автообновление", scheduleState(schedule))
	}

	if _, err := os.Stat(service.RsyslogConfigPath); err != nil {
		row("Статистика", dimText("не настроена"))
	} else if err := service.NewLoggingService(log()).CheckHealth(); err != nil {
		row("Статистика", warnText("не работает: "+err.Error()))
	} else {
		row("Статистика", okText("собирается")+dimText(" — rkn-guard stats"))
	}
	return w.Flush()
}

func scheduleState(s service.Schedule) string {
	active, enabled := service.NewScheduleService(log(), service.BinaryPath).TimerState()
	text := s.String()
	switch {
	case s.Mode == service.ScheduleOff && active:
		return text + warnText(" — но таймер всё ещё активен")
	case s.Mode == service.ScheduleOff:
		return dimText(text)
	case active && enabled:
		return text
	case active:
		return text + warnText(" — до перезагрузки (таймер не включён)")
	}
	return text + warnText(" — таймер не запущен; sudo rkn-guard schedule ещё раз")
}

func moscow() *time.Location {
	if loc, err := time.LoadLocation("Europe/Moscow"); err == nil {
		return loc
	}
	return time.UTC
}
