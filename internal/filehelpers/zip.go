package filehelpers

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	// Import the password-supporting zip library
	yekaZip "github.com/yeka/zip"
)

// DecompressZip extracts a zip file to a destination directory,
// optionally using a password.
func DecompressZip(sourcePath, destinationDir, password string) error {
	// 1. Create the destination directory if it doesn't exist
	if err := os.MkdirAll(destinationDir, 0755); err != nil {
		return fmt.Errorf("failed to create destination directory: %w", err)
	}

	// 2. Open the ZIP archive using the password-supporting reader
	r, err := yekaZip.OpenReader(sourcePath)
	if err != nil {
		return fmt.Errorf("failed to open zip file: %w", err)
	}
	defer r.Close()

	// 3. Iterate through the files in the archive
	for _, f := range r.File {
		// Construct the full path for the destination file
		fpath := filepath.Join(destinationDir, f.Name)

		// --- Zip Slip Vulnerability Check ---
		// Ensure file path is under the destination (prevents overwriting system files)
		if !strings.HasPrefix(fpath, filepath.Clean(destinationDir)+string(os.PathSeparator)) {
			return fmt.Errorf("illegal file path in zip: %s", f.Name)
		}

		// Handle directories
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(fpath, os.ModePerm); err != nil {
				return err
			}
			continue
		}

		// Handle regular files
		// Create parent directories if they don't exist
		if err := os.MkdirAll(filepath.Dir(fpath), os.ModePerm); err != nil {
			return err
		}

		// Set the password if one is provided AND the file is encrypted
		// The IsEncrypted() check is good practice but optional, as SetPassword
		// on a non-encrypted file is typically harmless.
		if password != "" && f.IsEncrypted() {
			f.SetPassword(password)
		} else if f.IsEncrypted() && password == "" {
			// Fail if the file is encrypted but no password was provided
			return fmt.Errorf("file is password-protected, but no password was provided: %s", f.Name)
		}

		// Open the file inside the ZIP archive
		rc, err := f.Open()
		if err != nil {
			// This is where decryption failure errors usually occur
			return fmt.Errorf("failed to open file in zip (%s). Check password: %w", f.Name, err)
		}

		// Create the destination file
		outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			rc.Close()
			return fmt.Errorf("failed to create destination file (%s): %w", fpath, err)
		}

		// Copy data
		_, err = io.Copy(outFile, rc)

		// Close readers/writers
		outFile.Close()
		rc.Close()

		if err != nil {
			return fmt.Errorf("failed to copy file content (%s): %w", f.Name, err)
		}
	}

	fmt.Printf("Successfully decompressed '%s' to '%s'\n", sourcePath, destinationDir)
	return nil
}
