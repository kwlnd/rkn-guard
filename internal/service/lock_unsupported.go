//go:build !linux

package service

import (
	"fmt"
	"os"
	"time"
)

// Тесты можно запускать на любой ОС, но работу с firewall разрешаем только в Linux.
func AcquireLock(time.Duration, func()) (*os.File, error) {
	return nil, fmt.Errorf("firewall operations require Linux")
}
