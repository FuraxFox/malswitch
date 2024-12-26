// Malswitch : a small malware collection manager
// license that can be found in the LICENSE file.

// Component

package catalog

import (
	"database/sql"
	"fmt"
	"path/filepath"

	"github.com/FuraxFox/malswitch/internal/analysis"
	"github.com/FuraxFox/malswitch/internal/filehelpers"
	"github.com/FuraxFox/malswitch/internal/manifest"
	"github.com/FuraxFox/malswitch/internal/submissions"
	log "github.com/sirupsen/logrus"
)

type CatalogEntry struct {
	manifest *manifest.Manifest
	name     string
	existing bool
}

func (cat *CatalogEntry) Name() string {
	return cat.name
}

func (cat *CatalogEntry) SamplePath(catalogRoot string) string {
	return filepath.Join(catalogRoot, cat.name, cat.manifest.SHA256+".bin")
}

func CreateOrUpdateEntry(sub *submissions.Submission, subDir, catDir string) (*CatalogEntry, error) {

	log.Debug("creating a catalog entry<" + sub.SHA256 + "> from sub <" + sub.UUID + ">")
	m := manifest.CreateFromSubmission(sub)

	cat := CatalogEntry{
		manifest: m,
		name:     sub.SHA256,
	}

	entryPath := filepath.Join(catDir, cat.name)

	existing, err := filehelpers.CreateDirIfNotExist(entryPath)
	if err != nil {
		log.Error("error processing submission <"+cat.manifest.UUID+"> to catalog:", err)
		return nil, err
	}
	cat.existing = existing

	err = cat.importSample(sub, subDir, catDir)
	if err != nil {
		log.Error("error importing sample from submission <"+cat.manifest.UUID+"> to catalog:", err)
		return nil, err
	}

	return &cat, nil
}

func (cat *CatalogEntry) importSample(sub *submissions.Submission, submissionsDir, catalogDir string) error {

	_, err := filehelpers.CopyFile(sub.QueuedSamplePath(submissionsDir), cat.SamplePath(catalogDir))
	if err != nil {
		log.Error("failed to copy submitted sample to the catalog directory:", err)
		return err
	}
	return nil
}

func (cat *CatalogEntry) EntryDir(catalogRoot string) string {
	return filepath.Join(catalogRoot, cat.name)
}

func (cat *CatalogEntry) Lock(catDir string) error {
	fullpath := filepath.Join(catDir, cat.name)
	return filehelpers.LockFile(fullpath)
}

func (cat *CatalogEntry) Unlock(catDir string) error {
	fullpath := filepath.Join(catDir, cat.name)
	return filehelpers.UnlockFile(fullpath)
}

func (cat *CatalogEntry) Analyze(catDir string) error {
	fileToAnalyze := cat.SamplePath(catDir)
	log.Debug(">> analyzing catalog entry<" + cat.name + "> :" + fileToAnalyze)
	//TODO some aditionnal analysis
	// TODO create a list of analyzers to run sequentially
	err := analysis.AnalyseMimeType(catDir, cat.manifest)
	if err != nil {
		log.Warn("Analysis failed ", err)
	}
	return nil
}

// Save a catalog entry to the catalog directory
func (cat *CatalogEntry) Save(catDir string) error {
	log.Debug(">> saving catalog entry:" + cat.name + " to '" + catDir + "'")

	entryPath := filepath.Join(catDir, cat.name)

	existing, err := filehelpers.CreateDirIfNotExist(entryPath)
	if err != nil {
		log.Error("error processing submission <"+cat.name+"> to catalog:", err)
		return err
	}
	if existing {
		//TODO update history
		log.Debug("merging a new submission in an existing one")
	}
	err = cat.manifest.Save(entryPath)
	if err != nil {
		log.Error("error processing submission <"+cat.name+"> to catalog:", err)
		return err
	}

	return nil
}

// Save a catalog entry to the catalog database
func (cat *CatalogEntry) Register(Db *sql.DB) error {

	// Insert the data into the database
	_, err := Db.Exec(
		"INSERT INTO catalog (uuid, md5, sha1, sha256, sha512, size, filename, tlp) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
		cat.manifest.UUID,
		cat.manifest.MD5, cat.manifest.SHA1, cat.manifest.SHA256, cat.manifest.SHA512,
		cat.manifest.Size, cat.manifest.Filename, cat.manifest.TLP)
	log.Debug("registering: " + cat.manifest.UUID + "(TLP:" + cat.manifest.TLP + ", size:" + fmt.Sprintf("%d", cat.manifest.Size) + ")")
	if err != nil {
		log.Error("error registering catalog entryto database for <"+cat.name+">: ", err)
		return err
	}

	return nil
}
