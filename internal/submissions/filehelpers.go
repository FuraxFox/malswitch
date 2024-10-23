// Malswitch : a small malware collection manager
// license that can be found in the LICENSE file.

// Submissions: manage user submissions queue

package submissions

import (
	"fmt"
	"os"
	"time"
)

func LockFile(filename string) error {
	lock := filename + ".lock"

	// Try to acquire the lock
	locked := false
	for !locked {
		err := os.Mkdir(lock, os.ModePerm)
		if err != nil {
			if os.IsExist(err) {
				// Lock already exists, wait for a short time and retry
				time.Sleep(100 * time.Millisecond)
			} else {
				fmt.Println("Error creating lock file:", err)
				return err
			}
		} else {
			locked = true
		}
	}
	return nil
}
func UnlockFile(filename string) error {
	lockfile := filename + ".lock"
	return os.RemoveAll(lockfile)
}

func CreateDirIfNotExist(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		err = os.Mkdir(path, 0700)
		if err != nil {
			return err
		}
	}
	return nil
}
