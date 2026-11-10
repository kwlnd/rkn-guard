package service

import (
	"errors"
	"os"
	"strings"
)

const (
	BinaryPath        = "/usr/local/bin/rkn-guard"
	ShortCommandPath  = "/usr/local/bin/rkn"
	legacyManagerPath = "/opt/rkn-guard-manager.sh"
)

// LinkShortCommand делает rkn ссылкой на rkn-guard. Старую обёртку баш-меню
// заменяет; чужой файл с тем же именем не трогает.
func LinkShortCommand() error {
	if target, err := os.Readlink(ShortCommandPath); err == nil {
		if target == BinaryPath {
			return nil
		}
	} else if data, err := os.ReadFile(ShortCommandPath); err == nil {
		if !strings.Contains(string(data), legacyManagerPath) {
			return nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	tmp := ShortCommandPath + ".new"
	_ = os.Remove(tmp)
	if err := os.Symlink(BinaryPath, tmp); err != nil {
		return err
	}
	return os.Rename(tmp, ShortCommandPath)
}

// RemoveShortCommand удаляет rkn, только если это наша ссылка или старая обёртка.
func RemoveShortCommand() error {
	if target, err := os.Readlink(ShortCommandPath); err == nil {
		if target == BinaryPath {
			return removeFileIfExists(ShortCommandPath)
		}
		return nil
	}
	if data, err := os.ReadFile(ShortCommandPath); err == nil && strings.Contains(string(data), legacyManagerPath) {
		return removeFileIfExists(ShortCommandPath)
	}
	return nil
}

// RemoveLegacyManager удаляет баш-меню прежних версий.
func RemoveLegacyManager() error {
	return removeFileIfExists(legacyManagerPath)
}
