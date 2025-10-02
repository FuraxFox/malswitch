package filehelpers

import (
	"os"
	"path/filepath"
	"testing"

	// You will need this package installed to run the tests
	yekaZip "github.com/yeka/zip"
)

// Define constants for test files and directories
const (
	TestDir         = "testdata"
	TestFile1       = "file1.txt"
	TestFile2       = "dir/file2.txt"
	DestDir         = "extracted_test"
	ZipNoPass       = "test_nopass.zip"
	ZipWithPass     = "test_withpass.zip"
	CorrectPassword = "secretpass"
)

// Helper function to create the dummy ZIP files for testing
func createTestZip(t *testing.T, zipName, password string) {
	// Ensure the test directory exists
	if err := os.MkdirAll(TestDir, 0755); err != nil {
		t.Fatalf("Failed to create test dir: %v", err)
	}

	zipPath := filepath.Join(TestDir, zipName)
	newZipFile, err := os.Create(zipPath)
	if err != nil {
		t.Fatalf("Failed to create zip file: %v", err)
	}
	defer newZipFile.Close()

	zipWriter := yekaZip.NewWriter(newZipFile)
	defer zipWriter.Close()

	// --- 1. Add TestFile1 (root level) ---
	// Create header
	header1 := &yekaZip.FileHeader{
		Name:   TestFile1,
		Method: yekaZip.Deflate,
		//	Modified: header1.Modified, // Preserve modification time
	}
	// Apply password if set
	if password != "" {
		header1.SetPassword(password)
	}

	writer1, err := zipWriter.CreateHeader(header1)
	if err != nil {
		t.Fatalf("Failed to create header 1: %v", err)
	}
	_, err = writer1.Write([]byte("Content of the first test file."))
	if err != nil {
		t.Fatalf("Failed to write content 1: %v", err)
	}

	// --- 2. Add TestFile2 (nested directory) ---
	// Create header
	header2 := &yekaZip.FileHeader{
		Name:   TestFile2,
		Method: yekaZip.Deflate,
		//		Modified: header2.Modified, // Preserve modification time
	}
	// Apply password if set
	if password != "" {
		header2.SetPassword(password)
	}

	writer2, err := zipWriter.CreateHeader(header2)
	if err != nil {
		t.Fatalf("Failed to create header 2: %v", err)
	}
	_, err = writer2.Write([]byte("Content of the second test file, in a subdirectory."))
	if err != nil {
		t.Fatalf("Failed to write content 2: %v", err)
	}
}

// setup and teardown function
func setup(t *testing.T) {
	// Create the test ZIP files
	createTestZip(t, ZipNoPass, "")
	createTestZip(t, ZipWithPass, CorrectPassword)
}

func teardown() {
	// Clean up the entire test directory (including zips and extracted content)
	os.RemoveAll(TestDir)
	os.RemoveAll(DestDir)
}

// TestDecompressZip is the main test function for DecompressZip
func TestDecompressZip(t *testing.T) {
	// Run setup before the tests and teardown after
	setup(t)
	defer teardown()

	tests := []struct {
		name         string
		source       string
		password     string
		expectError  bool
		expectedFile string
	}{
		{
			name:         "Success_NoPassword",
			source:       filepath.Join(TestDir, ZipNoPass),
			password:     "",
			expectError:  false,
			expectedFile: filepath.Join(DestDir, TestFile1),
		},
		{
			name:         "Success_WithPassword",
			source:       filepath.Join(TestDir, ZipWithPass),
			password:     CorrectPassword,
			expectError:  false,
			expectedFile: filepath.Join(DestDir, TestFile2), // Check nested file
		},
		{
			name:         "Failure_WrongPassword",
			source:       filepath.Join(TestDir, ZipWithPass),
			password:     "wrongpass",
			expectError:  true,
			expectedFile: filepath.Join(DestDir, TestFile1), // File shouldn't exist/be readable
		},
		{
			name:         "Failure_MissingFile",
			source:       filepath.Join(TestDir, "nonexistent.zip"),
			password:     "",
			expectError:  true,
			expectedFile: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear the destination directory before each test run
			os.RemoveAll(DestDir)

			err := DecompressZip(tt.source, DestDir, tt.password)

			if tt.expectError {
				if err == nil {
					t.Errorf("DecompressZip expected an error but got nil")
				}
				// Skip file existence check if an error was expected/received
				return
			}

			// If no error was expected, check for error and file existence
			if err != nil {
				t.Fatalf("DecompressZip unexpected error: %v", err)
			}

			// Check if the expected file was extracted
			if _, err := os.Stat(tt.expectedFile); os.IsNotExist(err) {
				t.Errorf("DecompressZip failed to extract expected file: %s", tt.expectedFile)
			}

			// Optional: Check if directory structure was created correctly
			expectedDir := filepath.Join(DestDir, "dir")
			if _, err := os.Stat(expectedDir); os.IsNotExist(err) {
				t.Errorf("DecompressZip failed to create expected directory: %s", expectedDir)
			}
		})
	}
}
