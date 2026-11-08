//go:build windows

package runs

import "os"

// Alive says the process that started a run that has not finished is still there.
func Alive(r Record) bool {
	if r.Pid <= 0 {
		return false
	}
	p, err := os.FindProcess(r.Pid)
	if err != nil {
		return false
	}
	p.Release()
	return true
}
