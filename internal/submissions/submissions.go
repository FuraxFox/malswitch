// Malswitch : a small malware collection manager
// license that can be found in the LICENSE file.

// Submissions: manage user submissions queue

package submissions

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"os"
	"time"

	"path/filepath"

	"github.com/google/uuid"
	"gopkg.in/yaml.v2"
)

type Submission struct {
	UUID       string
	MD5        string
	SHA1       string
	SHA256     string
	SHA512     string
	TLP        string
	Filename   string
	TempPath   string `json:"-" yaml:"-"`
	QueuedPath string `json:"-" yaml:"-"`
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

func Create(sampleFilename string, sampleTLP string, tempDir string, queueDir string) (*Submission, error) {
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

func computeHash(f *os.File, algo hash.Hash) (string, error) {

	_, err := io.Copy(algo, f)
	if err != nil {
		return "", err
	}
	hashBytes := algo.Sum(nil)
	hashString := fmt.Sprintf("%x", hashBytes)

	return hashString, nil
}

// Calculate the various basic hashes of the file
func (s *Submission) Hash() error {

	f, err := os.Open(s.TempFilePath())
	if err != nil {
		return err
	}
	defer f.Close()

	hashString, err := computeHash(f, md5.New())
	if err != nil {
		return err
	}
	s.MD5 = hashString

	hashString, err = computeHash(f, sha1.New())
	if err != nil {
		return err
	}
	s.SHA1 = hashString

	hashString, err = computeHash(f, sha256.New())
	if err != nil {
		return err
	}
	s.SHA256 = hashString

	hashString, err = computeHash(f, sha512.New())
	if err != nil {
		return err
	}
	s.SHA512 = hashString

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

	s.SaveManifest(queuePath)
	// TODO create history
	return nil
}

func (s *Submission) GetYAML() ([]byte, error) {
	yamlData, err := yaml.Marshal(&s)
	if err != nil {
		return nil, err
	}
	return yamlData, nil
}

func (s *Submission) GetJSON() ([]byte, error) {
	jsonData, err := json.Marshal(&s)
	if err != nil {
		return nil, err
	}
	return jsonData, nil
}

func (s *Submission) SaveManifest(dir string) error {
	// TODO
	yamlData, err := s.GetYAML()
	if err != nil {
		return err
	}

	filePath := filepath.Join(dir, "Submission.yaml")

	err = os.WriteFile(filePath, yamlData, 0644)
	if err != nil {
		return err
	}

	return nil
}

func (s *Submission) Lock() error {
	lock := s.QueuedPath + ".lock"

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

func (s *Submission) Unlock() error {
	lock := s.QueuedPath + ".lock"
	err := os.RemoveAll(lock)
	return err
}

func Read(queuePath string) (*Submission, error) {

	// TODO

	// Read the YAML content
	data, err := os.ReadFile(filepath.Join(queuePath, "Submission.yaml"))
	if err != nil {
		return nil, err
	}
	// Parse the YAML content
	//var yamlData interface{}
	var yamlData Submission
	err = yaml.Unmarshal(data, &yamlData)
	if err != nil {
		return nil, err
	}

	return &yamlData, nil
}
