package writer

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDeleteTempFile(t *testing.T) {
	// Setup
	testFilename := "testfile.tmp"
	testFilePath := filepath.Join("/tmp", testFilename)
	os.WriteFile(testFilePath, []byte("test data"), 0644)

	w := &_Writer{} // Assuming _Writer doesn't need initialization for this method

	// Execute
	err := w.DeleteTempFile(testFilename)

	// Assert
	assert.NoError(t, err)

	// Check if file is really deleted
	_, err = os.Stat(testFilePath)
	assert.True(t, os.IsNotExist(err))
}
