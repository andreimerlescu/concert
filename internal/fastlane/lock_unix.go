//go:build !windows

package fastlane

import (
	"os"
	"syscall"
)

func lockJournal(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
}
func unlockJournal(f *os.File) { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }

// syncDir makes a newly created journal's directory entry durable.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
