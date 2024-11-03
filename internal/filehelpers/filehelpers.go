// Malswitch : a small malware collection manager
// license that can be found in the LICENSE file.

// filehelpers: manage user submissions queue

package filehelpers

import (
	"fmt"
	"io"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
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
				log.Error("error creating lock file:", err)
				return err
			}
		} else {
			log.Debug("'" + filename + "' locked")
			locked = true
		}
	}
	return nil
}
func UnlockFile(filename string) error {
	lockfile := filename + ".lock"
	err := os.RemoveAll(lockfile)
	if err != nil {
		log.Warning("Failed to un lock '"+filename+"'", err)
	} else {
		log.Debug("'" + filename + "' unlocked")
	}
	return err
}

func CreateDirIfNotExist(path string) (bool, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		err = os.Mkdir(path, 0700)
		if err != nil {
			return false, err
		}
		return false, nil
	}
	return true, nil
}

func CopyFile(src, dst string) (int64, error) {
	sourceFileStat, err := os.Stat(src)
	if err != nil {
		return 0, err
	}

	if !sourceFileStat.Mode().IsRegular() {
		return 0, fmt.Errorf("%s is not a regular file", src)
	}

	source, err := os.Open(src)
	if err != nil {
		return 0, err
	}
	defer source.Close()

	destination, err := os.Create(dst)
	if err != nil {
		return 0, err
	}
	defer destination.Close()
	nBytes, err := io.Copy(destination, source)

	return nBytes, err
}
