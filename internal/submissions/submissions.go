// Malswitch : a small malware collection manager
// license that can be found in the LICENSE file.

// Submissions: manage user submissions queue

package submissions

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"

	"path/filepath"

	"github.com/google/uuid"
)

type Submission struct {
	UUID     string
	SHA256   string
	TLP      string
	Filename string
	TempPath string
}

func createDirIfNotExist(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		err = os.Mkdir(path, 0700)
		if err != nil {
			return err
		}
	}
	return nil
}

func Create(sampleFilename string, sampleTLP string, tempDir string) (*Submission, error) {
	s := Submission{
		Filename: sampleFilename,
		TLP:      sampleTLP,
	}
	s.UUID = uuid.NewString()
	s.TempPath = filepath.Join(tempDir, s.UUID)

	err := createDirIfNotExist(s.TempPath)
	if err != nil {
		return nil, err
	}

	return &s, nil
}

// Calculate the SHA256 hash of the file
func (s *Submission) Hash() error {

	f, err := os.Open(s.TempFilePath())
	if err != nil {
		return err
	}
	defer f.Close()

	hash := sha256.New()
	_, err = io.Copy(hash, f)
	if err != nil {
		return err
	}

	hashBytes := hash.Sum(nil)
	hashString := fmt.Sprintf("%x", hashBytes)

	s.SHA256 = hashString

	return nil
}

func (s *Submission) TempFilePath() string {
	return filepath.Join(s.TempPath, s.UUID+".bin")
}

func (s *Submission) Enqueue(queueRoot string) error {

	// creating queue entry directory <queue>/<uuid>
	queuePath := filepath.Join(queueRoot, s.UUID)
	err := createDirIfNotExist(queuePath)
	if err != nil {
		return err
	}

	// moving the file to <queue>/<uuid>/<sha256>.bin
	queueFilename := filepath.Join(queuePath, s.SHA256+".bin")
	err = os.Rename(s.TempFilePath(), queueFilename)
	if err != nil {
		return err
	}

	// cleanup
	err = os.Remove(s.TempPath)
	if err != nil {
		return err
	}

	// TODO create manifest
	// TODO create history
	return nil
}
