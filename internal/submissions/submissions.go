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
	_ "net/http"
	"os"

	"path/filepath"

	"github.com/FuraxFox/malswitch/internal/filehelpers"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

type Submission struct {
	UUID     string `yaml:"uuid"     json:"uuid"`
	MD5      string `yaml:"md5"      json:"md5"`
	SHA1     string `yaml:"sha1"     json:"sha1"`
	SHA256   string `yaml:"sha256"   json:"sha256"`
	SHA512   string `yaml:"sha512"   json:"sha512"`
	TLP      string `yaml:"tlp"      json:"tlp"`
	Size     int64  `yaml:"size"     json:"size"`
	Filename string `yaml:"filename" json:"filename"`
	TempPath string `json:"-" yaml:"-"`
}

func Create(sampleFilename string, sampleTLP string, queueDir string, tempDir string) (*Submission, error) {
	s := Submission{
		Filename: sampleFilename,
		TLP:      sampleTLP,
	}
	s.UUID = uuid.NewString()
	tempPath := filepath.Join(tempDir, s.UUID)

	_, err := filehelpers.CreateDirIfNotExist(tempPath)
	if err != nil {
		log.Error("failed to create submission directory:", err)
		return nil, err
	}

	return &s, nil
}

func computeHash(f *os.File, algo hash.Hash) (string, error) {
	// sending bytes to hasher
	_, err := io.Copy(algo, f)
	if err != nil {
		log.Error("failed to copy file descriptor to compute hash:", err)
		return "", err
	}
	// rewinding file
	f.Seek(0, io.SeekStart)

	// getting sum in hex
	hashBytes := algo.Sum(nil)
	hashString := fmt.Sprintf("%x", hashBytes)

	return hashString, nil
}

// Calculate the various basic hashes of the file
func (s *Submission) Hash(tempRoot string) error {

	// opening submitted file
	binaryPath := s.TempSamplePath(tempRoot)
	f, err := os.Open(binaryPath)
	if err != nil {
		log.Error("failed to open '"+binaryPath+"':", err)
		return err
	}
	defer f.Close()

	// hashing with various standard algorithms
	hashString, err := computeHash(f, md5.New())
	if err != nil {
		log.Error("failed to compute MD5 hash:", err)
		return err
	}
	s.MD5 = hashString

	hashString, err = computeHash(f, sha1.New())
	if err != nil {
		log.Error("failed to compute SHA1 hash:", err)
		return err
	}
	s.SHA1 = hashString

	hashString, err = computeHash(f, sha256.New())
	if err != nil {
		log.Error("failed to compute SHA256 hash:", err)
		return err
	}
	s.SHA256 = hashString

	hashString, err = computeHash(f, sha512.New())
	if err != nil {
		log.Error("failed to compute SHA512 hash:", err)
		return err
	}
	s.SHA512 = hashString

	return nil
}

func (s *Submission) TempDirPath(tempRoot string) string {
	return filepath.Join(tempRoot, s.UUID)
}

func (s *Submission) TempSamplePath(tempRoot string) string {
	return filepath.Join(tempRoot, s.UUID, s.UUID+".bin")
}

func (s *Submission) QueuedPath(queueRoot string) string {
	queuePath := filepath.Join(queueRoot, s.UUID)
	return queuePath
}

func (s *Submission) QueuedSamplePath(queueRoot string) string {
	queuePath := filepath.Join(queueRoot, s.UUID, s.SHA256+".bin")
	return queuePath
}

func (s *Submission) Receive(file io.Reader /*file multipart.File*/, tempRoot string) error {

	destFPath := s.TempSamplePath(tempRoot) // TODO pass a context to the server

	// Create a new file on disk
	newFile, err := os.Create(destFPath)
	if err != nil {
		log.Error("error creating file to receive submission:", err)
		return err
	}
	log.Debug("received file stored as: " + destFPath)
	defer newFile.Close()

	// save the uploaded file to the new file
	_, err = io.Copy(newFile, file)
	if err != nil {
		log.Error("error receiving data while for submission:", err)
		return err
	}

	// compute file size
	fi, err := newFile.Stat()
	if err != nil {
		log.Error("error calculating file size:", err)
		return err
	}
	s.Size = fi.Size()

	return nil
}

func (s *Submission) Dequeue(queueRoot string) error {
	err := s.Lock(queueRoot)
	if err != nil {
		log.Error("failed to get lock on submission to enqueue:", err)
		return err
	}
	defer s.Unlock(queueRoot)

	// Remove the file if insertion succeeded
	err = os.RemoveAll(s.QueuedPath(queueRoot))
	if err != nil {
		log.Error("error removing file:", err)
		return err
	}
	return nil
}

func (s *Submission) Enqueue(queueRoot string, tempRoot string) error {

	err := s.Lock(queueRoot)
	if err != nil {
		log.Error("failed to get lock on submission to enqueue:", err)
		return err
	}
	defer s.Unlock(queueRoot)

	// creating queue entry directory <queue>/<uuid>
	queuePath := s.QueuedPath(queueRoot)
	_, err = filehelpers.CreateDirIfNotExist(queuePath)
	if err != nil {
		log.Error("failed to create submission directory:", err)
		return err
	}

	// moving the file to <queue>/<uuid>/<sha256>.bin
	queueFilename := s.QueuedSamplePath(queueRoot)
	tempFilename := s.TempSamplePath(tempRoot)
	err = os.Rename(tempFilename, queueFilename)
	if err != nil {
		log.Error("failed to move submission to the queue directory:", err)
		return err
	}
	log.Debug("submitted data file moved from: " + s.TempSamplePath(tempRoot) + "  to:" + queueFilename)

	err = s.SaveManifest(queuePath)
	if err != nil {
		log.Error("failed to save submission manifest:", err)
		return err
	}
	log.Debug("manifest saved to " + queuePath)

	// cleanup
	tempPath := s.TempDirPath(tempRoot)
	err = os.RemoveAll(tempPath)
	if err != nil {
		log.Error("failed to remove temporary submission files:", err)
		return err
	}
	log.Debug("submission temporary path " + tempPath + " cleaned up")
	return err
}

func (s *Submission) GetYAML() ([]byte, error) {
	yamlData, err := yaml.Marshal(&s)
	if err != nil {
		log.Error("failed to encode submission to YAML:", err)
		return nil, err
	}
	return yamlData, nil
}

func (s *Submission) GetJSON() ([]byte, error) {
	jsonData, err := json.Marshal(&s)
	if err != nil {
		log.Error("failed to encode submission to JSON:", err)
		return nil, err
	}
	return jsonData, nil
}

func (s *Submission) SaveManifest(dir string) error {
	// TODO
	yamlData, err := s.GetYAML()
	if err != nil {
		log.Error("failed to save submission manifest:", err)
		return err
	}

	filePath := filepath.Join(dir, "Submission.yaml")
	err = os.WriteFile(filePath, yamlData, 0644)
	if err != nil {
		log.Error("failed to write submission manifest:", err)
		return err
	}
	log.Debug("submission manifest saved to " + filePath)

	return nil
}

func (s *Submission) Lock(queueRoot string) error {
	return filehelpers.LockFile(s.QueuedPath(queueRoot))
}

func (s *Submission) Unlock(queueRoot string) error {
	return filehelpers.UnlockFile(s.QueuedPath(queueRoot))
}

func Read(queuePath string) (*Submission, error) {
	err := filehelpers.LockFile(queuePath)
	if err != nil {
		log.Error("failed to lock submission for reading:", err)
		return nil, err
	}
	defer filehelpers.UnlockFile(queuePath)

	// Read the YAML content
	data, err := os.ReadFile(filepath.Join(queuePath, "Submission.yaml"))
	if err != nil {
		log.Error("failed to read submission data:", err)
		return nil, err
	}
	// Parse the YAML content
	//var sub interface{}
	var sub Submission
	err = yaml.Unmarshal(data, &sub)
	if err != nil {
		log.Error("failed to decode submission data:", err)
		return nil, err
	}

	return &sub, nil
}
