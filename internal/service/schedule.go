package service

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/rs/zerolog"
)

const (
	ScheduleConfigPath  = "/etc/rkn-guard-update.conf"
	UpdateTimerName     = "rkn-guard-update.timer"
	UpdateServiceName   = "rkn-guard-update.service"
	systemdUnitDir      = "/etc/systemd/system"
	maxScheduleTimes    = 24
	maxScheduleInterval = 168
)

// Режимы файла настроек совпадают со старым меню, чтобы старые установки читались.
const (
	ScheduleOff      = "off"
	ScheduleInterval = "interval" // каждые N часов
	ScheduleMSK      = "hours"    // ежедневно в заданное время по Москве
	ScheduleLocal    = "local"    // ежедневно по локальному времени сервера
	scheduleLegacy   = "msk"      // старое «06:00 МСК»
)

// Schedule описывает автообновление списков.
type Schedule struct {
	Mode  string
	Hours int      // для interval
	Times []string // ЧЧ:ММ для hours/local
}

var timePattern = regexp.MustCompile(`^([0-9]{1,2})(?::([0-9]{2}))?$`)

// ParseTimes принимает «6,12» или «06:00, 18:30» и возвращает отсортированные ЧЧ:ММ.
func ParseTimes(value string) ([]string, error) {
	seen := map[string]bool{}
	var result []string
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		match := timePattern.FindStringSubmatch(item)
		if match == nil {
			return nil, fmt.Errorf("%q: время пишется как 6, 06:00 или 18:30", item)
		}
		hour, _ := strconv.Atoi(match[1])
		minute := 0
		if match[2] != "" {
			minute, _ = strconv.Atoi(match[2])
		}
		if hour > 23 || minute > 59 {
			return nil, fmt.Errorf("%q: нет такого времени", item)
		}
		normal := fmt.Sprintf("%02d:%02d", hour, minute)
		if !seen[normal] {
			seen[normal] = true
			result = append(result, normal)
		}
	}
	if len(result) > maxScheduleTimes {
		return nil, fmt.Errorf("не больше %d запусков в сутки", maxScheduleTimes)
	}
	sort.Strings(result)
	return result, nil
}

// ParseInterval проверяет интервал в часах.
func ParseInterval(value string) (int, error) {
	hours, err := strconv.Atoi(strings.TrimSuffix(strings.TrimSpace(value), "h"))
	if err != nil || hours < 1 || hours > maxScheduleInterval {
		return 0, fmt.Errorf("интервал — целое число часов от 1 до %d", maxScheduleInterval)
	}
	return hours, nil
}

// LoadSchedule читает настройки. Отсутствие файла означает «выключено».
func LoadSchedule() (Schedule, error) {
	return loadSchedule(ScheduleConfigPath)
}

func loadSchedule(path string) (Schedule, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Schedule{Mode: ScheduleOff}, nil
	}
	if err != nil {
		return Schedule{}, err
	}
	line := strings.TrimSpace(string(data))
	mode, value, ok := strings.Cut(line, "=")
	if !ok || strings.Contains(line, "\n") {
		return Schedule{}, fmt.Errorf("повреждён %s", path)
	}
	switch mode {
	case ScheduleOff:
		return Schedule{Mode: ScheduleOff}, nil
	case ScheduleInterval:
		hours, err := ParseInterval(value)
		if err != nil {
			return Schedule{}, fmt.Errorf("%s: %w", path, err)
		}
		return Schedule{Mode: mode, Hours: hours}, nil
	case ScheduleMSK, ScheduleLocal, scheduleLegacy:
		times, err := ParseTimes(value)
		if err != nil {
			return Schedule{}, fmt.Errorf("%s: %w", path, err)
		}
		if mode == scheduleLegacy {
			mode = ScheduleMSK
		}
		return Schedule{Mode: mode, Times: times}, nil
	}
	return Schedule{}, fmt.Errorf("%s: неизвестный режим %q", path, mode)
}

func (s Schedule) configLine() string {
	switch s.Mode {
	case ScheduleInterval:
		return fmt.Sprintf("%s=%d\n", s.Mode, s.Hours)
	case ScheduleMSK, ScheduleLocal:
		return s.Mode + "=" + strings.Join(s.Times, ",") + "\n"
	}
	return "off=\n"
}

// String — описание для вывода пользователю.
func (s Schedule) String() string {
	switch s.Mode {
	case ScheduleInterval:
		return fmt.Sprintf("каждые %d ч.", s.Hours)
	case ScheduleMSK:
		return "ежедневно в " + strings.Join(s.Times, ", ") + " МСК"
	case ScheduleLocal:
		return "ежедневно в " + strings.Join(s.Times, ", ") + " (время сервера)"
	}
	return "выключено"
}

func updateServiceUnit(binary string) string {
	return fmt.Sprintf(`[Unit]
Description=rkn-guard subnet list update
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=%s update
# 2 — списки обновлены, но часть источников недоступна: это не сбой службы.
SuccessExitStatus=2
StandardInput=null
`, binary)
}

func (s Schedule) timerUnit() string {
	var b strings.Builder
	b.WriteString("[Unit]\nDescription=rkn-guard subnet update schedule\n\n[Timer]\n")
	if s.Mode == ScheduleInterval {
		fmt.Fprintf(&b, "OnActiveSec=%dh\nOnUnitActiveSec=%dh\n", s.Hours, s.Hours)
	} else {
		for _, t := range s.Times {
			if s.Mode == ScheduleLocal {
				fmt.Fprintf(&b, "OnCalendar=*-*-* %s:00\n", t)
			} else {
				fmt.Fprintf(&b, "OnCalendar=*-*-* %s:00 Europe/Moscow\n", t)
			}
		}
		b.WriteString("Persistent=true\n")
	}
	b.WriteString("RandomizedDelaySec=2min\nUnit=" + UpdateServiceName + "\n\n[Install]\nWantedBy=timers.target\n")
	return b.String()
}

// ScheduleService включает и выключает таймер автообновления.
type ScheduleService struct {
	logger  zerolog.Logger
	cmd     *CommandService
	unitDir string
	config  string
	binary  string
}

func NewScheduleService(logger zerolog.Logger, binary string) *ScheduleService {
	return &ScheduleService{logger: logger, cmd: NewCommandService(logger), unitDir: systemdUnitDir, config: ScheduleConfigPath, binary: binary}
}

// TimerState возвращает состояние таймера для status.
func (s *ScheduleService) TimerState() (active, enabled bool) {
	return s.cmd.RunQuiet("systemctl", "is-active", "--quiet", UpdateTimerName) == nil,
		s.cmd.RunQuiet("systemctl", "is-enabled", "--quiet", UpdateTimerName) == nil
}

// Apply записывает юниты и настройки. При ошибке возвращает прежние файлы.
func (s *ScheduleService) Apply(schedule Schedule) (result error) {
	servicePath := filepath.Join(s.unitDir, UpdateServiceName)
	timerPath := filepath.Join(s.unitDir, UpdateTimerName)
	backup := map[string][]byte{}
	for _, path := range []string{servicePath, timerPath, s.config} {
		if data, err := os.ReadFile(path); err == nil {
			backup[path] = data
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	wasActive, wasEnabled := s.TimerState()
	defer func() {
		if result == nil {
			return
		}
		for _, path := range []string{servicePath, timerPath, s.config} {
			if data, ok := backup[path]; ok {
				result = errors.Join(result, atomicWriteFile(path, data, 0644))
			} else {
				result = errors.Join(result, removeFileIfExists(path))
			}
		}
		_ = s.cmd.RunQuiet("systemctl", "daemon-reload")
		if wasEnabled {
			_ = s.cmd.RunQuiet("systemctl", "enable", UpdateTimerName)
		}
		if wasActive {
			_ = s.cmd.RunQuiet("systemctl", "start", UpdateTimerName)
		}
	}()

	if _, err := os.Stat(timerPath); err == nil || wasActive || wasEnabled {
		if err := s.cmd.Run("systemctl", "disable", "--now", UpdateTimerName); err != nil {
			return err
		}
	}
	if schedule.Mode == ScheduleOff {
		if err := errors.Join(removeFileIfExists(timerPath), removeFileIfExists(servicePath)); err != nil {
			return err
		}
	} else {
		if err := atomicWriteFile(servicePath, []byte(updateServiceUnit(s.binary)), 0644); err != nil {
			return err
		}
		if err := atomicWriteFile(timerPath, []byte(schedule.timerUnit()), 0644); err != nil {
			return err
		}
	}
	if err := s.cmd.Run("systemctl", "daemon-reload"); err != nil {
		return err
	}
	if schedule.Mode != ScheduleOff {
		if err := s.cmd.Run("systemctl", "enable", "--now", UpdateTimerName); err != nil {
			return err
		}
	}
	if schedule.Mode == ScheduleOff {
		return removeFileIfExists(s.config)
	}
	return atomicWriteFile(s.config, []byte(schedule.configLine()), 0644)
}

// RewriteService переписывает юнит обновления, если он ещё вызывает старое баш-меню.
func (s *ScheduleService) RewriteService() error {
	path := filepath.Join(s.unitDir, UpdateServiceName)
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	want := updateServiceUnit(s.binary)
	if string(data) == want {
		return nil
	}
	if err := atomicWriteFile(path, []byte(want), 0644); err != nil {
		return err
	}
	return s.cmd.Run("systemctl", "daemon-reload")
}
