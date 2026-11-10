package service

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestParseTimes(t *testing.T) {
	got, err := ParseTimes(" 18:30, 6,06:00 ,0")
	if err != nil || !reflect.DeepEqual(got, []string{"00:00", "06:00", "18:30"}) {
		t.Fatal(got, err)
	}
	for _, bad := range []string{"", "24", "6:7", "06:60", "6,,7", "noon"} {
		if _, err := ParseTimes(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestLoadLegacySchedule(t *testing.T) {
	dir := t.TempDir()
	for line, want := range map[string]string{
		"interval=6\n":        "каждые 6 ч.",
		"hours=06:00,18:30\n": "ежедневно в 06:00, 18:30 МСК",
		"msk=06:00\n":         "ежедневно в 06:00 МСК",
		"local=06:00\n":       "ежедневно в 06:00 (время сервера)",
		"off=\n":              "выключено",
	} {
		path := filepath.Join(dir, "conf")
		if err := os.WriteFile(path, []byte(line), 0600); err != nil {
			t.Fatal(err)
		}
		s, err := loadSchedule(path)
		if err != nil || s.String() != want {
			t.Errorf("%q: %q %v", line, s.String(), err)
		}
	}
	if s, err := loadSchedule(filepath.Join(dir, "missing")); err != nil || s.Mode != ScheduleOff {
		t.Fatal(s, err)
	}
}

func TestTimerUnit(t *testing.T) {
	unit := Schedule{Mode: ScheduleMSK, Times: []string{"06:00", "18:30"}}.timerUnit()
	if !strings.Contains(unit, "OnCalendar=*-*-* 18:30:00 Europe/Moscow\n") || !strings.Contains(unit, "Persistent=true") {
		t.Fatal(unit)
	}
	if unit := (Schedule{Mode: ScheduleInterval, Hours: 4}).timerUnit(); !strings.Contains(unit, "OnUnitActiveSec=4h") {
		t.Fatal(unit)
	}
	if svc := updateServiceUnit("/usr/local/bin/rkn-guard"); !strings.Contains(svc, "ExecStart=/usr/local/bin/rkn-guard update\n") {
		t.Fatal(svc)
	}
}
