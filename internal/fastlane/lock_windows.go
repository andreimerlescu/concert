//go:build windows

package fastlane

import (
	"os"

	"golang.org/x/sys/windows"
)

func lockJournal(f *os.File) error {
	return windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, new(windows.Overlapped))
}
func unlockJournal(f *os.File) {
	_ = windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, new(windows.Overlapped))
}

// syncDir is a no-op: Windows cannot open a directory for FlushFileBuffers,
// and NTFS journals directory entries itself.
func syncDir(string) error { return nil }
