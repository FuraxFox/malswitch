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

	"path/filepath"

	"github.com/google/uuid"
	"gopkg.in/yaml.v2"
)

type Submission struct {
	UUID       string `yaml:"uuid"`
	MD5        string `yaml:"md5"`
	SHA1       string `yaml:"sha1"`
	SHA256     string `yaml:"sha255"`
	SHA512     string `yaml:"sha512"`
	TLP        string `yaml:"tlp"`
	Filename   string `yaml:"filename"`
	TempPath   string `json:"-" yaml:"-"`
	QueuedPath string `json:"-" yaml:"-"`
}

func Create(sampleFilename string, sampleTLP string, tempDir string, queueDir string) (*Submission, error) {
	s := Submission{
		Filename: sampleFilename,
		TLP:      sampleTLP,
	}
	s.UUID = uuid.NewString()
	s.TempPath = filepath.Join(tempDir, s.UUID)

	err := CreateDirIfNotExist(s.TempPath)
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
func (s *Submission) Dequeue() error {
	// Remove the file if insertion succeeded
	err := os.RemoveAll(s.QueuedPath)
	if err != nil {
		fmt.Println("Error removing file:", err)
		return err
	}
	return nil
}

func (s *Submission) Enqueue(queueRoot string) error {
	err := s.Lock()
	if err != nil {
		return err
	}
	defer s.Unlock()

	// creating queue entry directory <queue>/<uuid>
	queuePath := filepath.Join(queueRoot, s.UUID)
	err = CreateDirIfNotExist(queuePath)
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
	return LockFile(s.QueuedPath)
}

func (s *Submission) Unlock() error {
	return UnlockFile(s.QueuedPath)
}

func Read(queuePath string) (*Submission, error) {
	err := LockFile(queuePath)
	if err != nil {
		return nil, err
	}
	defer UnlockFile(queuePath)

	// Read the YAML content
	data, err := os.ReadFile(filepath.Join(queuePath, "Submission.yaml"))
	if err != nil {
		return nil, err
	}
	// Parse the YAML content
	//var sub interface{}
	var sub Submission
	err = yaml.Unmarshal(data, &sub)
	if err != nil {
		return nil, err
	}
	sub.QueuedPath = queuePath

	return &sub, nil
}
