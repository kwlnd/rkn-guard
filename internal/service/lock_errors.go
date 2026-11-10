package service

import "errors"

// ErrLockTimeout — другая операция rkn-guard не закончилась за отведённое время.
var ErrLockTimeout = errors.New("другая операция rkn-guard не завершилась вовремя")
