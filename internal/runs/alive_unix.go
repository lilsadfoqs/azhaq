//go:build !windows

package runs

import "syscall"

// Alive says the process that started a run that has not finished is still there.
func Alive(r Record) bool {
	if r.Pid <= 0 {
		return false
	}
	err := syscall.Kill(r.Pid, 0)
	return err == nil || err == syscall.EPERM
}
