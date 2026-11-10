//go:build linux

package service

import (
	"errors"
	"os"
	"syscall"
	"time"
)

// AcquireLock не даёт изменять наборы и правила одновременно (ручные команды и
// таймер обновления). Если блокировка занята, ждёт до timeout; waiting
// вызывается один раз, чтобы сказать пользователю, почему пауза.
// Файл блокировки не удаляем: другой процесс может уже держать его открытым.
func AcquireLock(timeout time.Duration, waiting func()) (*os.File, error) {
	f, err := os.OpenFile("/run/rkn-guard.lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(timeout)
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return f, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			f.Close()
			return nil, err
		}
		if time.Now().After(deadline) {
			f.Close()
			return nil, ErrLockTimeout
		}
		if waiting != nil {
			waiting()
			waiting = nil
		}
		time.Sleep(250 * time.Millisecond)
	}
}
