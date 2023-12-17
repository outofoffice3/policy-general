package gotracker

import (
	"bufio"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestTracker(t *testing.T) {
	assert := assert.New(t)
	tracker := NewTracker()

	// Test tracking of a single goroutine and its defer call
	go func() {
		tracker.TrackGoroutine("testFunction", 1, "param")
		defer tracker.TrackDeferCall("testFunction", 1, "param")
		time.Sleep(100 * time.Millisecond) // Simulate work
	}()

	time.Sleep(50 * time.Millisecond) // Allow the goroutine to start
	active := tracker.ActiveGoroutines()
	assert.Equal(1, len(active), "Expected 1 active goroutine")

	time.Sleep(100 * time.Millisecond) // Allow the goroutine to complete
	assert.True(tracker.AreAllGoroutinesClosed(), "Expected all goroutines to be closed properly")

	// Test multiple goroutines
	for i := 0; i < 5; i++ {
		go func(i int) {
			tracker.TrackGoroutine("multipleTestFunction", i)
			defer tracker.TrackDeferCall("multipleTestFunction", i)
			time.Sleep(100 * time.Millisecond) // Simulate work
		}(i)
	}

	time.Sleep(50 * time.Millisecond) // Allow the goroutines to start
	active = tracker.ActiveGoroutines()
	assert.Equal(5, len(active), "Expected 5 active goroutines")

	time.Sleep(150 * time.Millisecond) // Allow the goroutines to complete
	assert.True(tracker.AreAllGoroutinesClosed(), "Expected all goroutines to be closed properly after multiple invocations")
}

func TestTrackerMismatch(t *testing.T) {
	assert := assert.New(t)
	tracker := NewTracker()

	// Test tracking mismatch between TrackGoroutine and TrackDeferCall
	go func() {
		tracker.TrackGoroutine("mismatchFunction", 1)
		defer tracker.TrackDeferCall("mismatchFunction") // Intentional mismatch
		time.Sleep(100 * time.Millisecond)               // Simulate work
	}()

	time.Sleep(200 * time.Millisecond) // Allow the goroutine to complete
	assert.False(tracker.AreAllGoroutinesClosed(), "Expected mismatch in tracking to result in unclosed goroutines")
}

func TestWriteActiveGoroutinesToCSV(t *testing.T) {
	assert := assert.New(t)
	tracker := NewTracker()

	// Start a tracked goroutine
	go func() {
		tracker.TrackGoroutine("TestFunction", 123)
		defer tracker.TrackDeferCall("TestFunction", 123)
		time.Sleep(50 * time.Millisecond)
	}()

	time.Sleep(25 * time.Millisecond) // Allow goroutine to start

	filePath := "active_goroutines_test.csv"
	err := tracker.WriteActiveGoroutinesToCSV(filePath)
	assert.NoError(err, "Writing active goroutines to CSV should not produce an error")

	// Verify the content of the CSV file
	file, err := os.Open(filePath)
	assert.NoError(err, "Opening the CSV file should not produce an error")
	defer file.Close()

	scanner := bufio.NewScanner(file)
	assert.True(scanner.Scan(), "The CSV file should have at least one line")
	assert.Contains(scanner.Text(), "TestFunction", "The CSV file should contain the tracked function name")

	// Clean up
	os.Remove(filePath)
}

func TestWriteAllGoroutinesToCSV(t *testing.T) {
	assert := assert.New(t)
	tracker := NewTracker()

	// Track a goroutine
	tracker.TrackGoroutine("TestFunctionAll", 456)

	filePath := "all_goroutines_test.csv"
	err := tracker.WriteAllGoroutinesToCSV(filePath)
	assert.NoError(err, "Writing all goroutines to CSV should not produce an error")

	// Verify CSV content
	verifyCSVContent(t, filePath, "TestFunctionAll")
	os.Remove(filePath) // Clean up
}

func TestWriteAllDefersToCSV(t *testing.T) {
	assert := assert.New(t)
	tracker := NewTracker()

	// Track a defer call
	tracker.TrackGoroutine("TestFunctionDefer", 789)
	tracker.TrackDeferCall("TestFunctionDefer", 789)

	filePath := "all_defers_test.csv"
	err := tracker.WriteAllDefersToCSV(filePath)
	assert.NoError(err, "Writing all defers to CSV should not produce an error")

	// Verify CSV content
	verifyCSVContent(t, filePath, "TestFunctionDefer")
	os.Remove(filePath) // Clean up
}

func verifyCSVContent(t *testing.T, filePath, expectedContent string) {
	assert := assert.New(t)

	file, err := os.Open(filePath)
	assert.NoError(err, "Opening the CSV file should not produce an error")
	defer file.Close()

	scanner := bufio.NewScanner(file)
	found := false
	for scanner.Scan() {
		if strings.Contains(scanner.Text(), expectedContent) {
			found = true
			break
		}
	}
	assert.True(found, "The CSV file should contain the expected content")
}

func TestWriteToNonExistentDirectory(t *testing.T) {
	assert := assert.New(t)
	tracker := NewTracker()

	// Assuming "/nonexistent" directory does not exist
	filePath := "/nonexistent/active_goroutines_test.csv"
	err := tracker.WriteActiveGoroutinesToCSV(filePath)
	assert.Error(err, "Writing to a non-existent directory should produce an error")
}

func TestWriteAllGoroutinesToCSVError(t *testing.T) {
	assert := assert.New(t)
	tracker := NewTracker()

	// Assuming "/nonexistent" directory does not exist
	filePath := "/nonexistent/all_goroutines_test.csv"
	err := tracker.WriteAllGoroutinesToCSV(filePath)
	assert.Error(err, "Writing all goroutines to CSV in a non-existent directory should produce an error")
}

func TestWriteAllDefersToCSVError(t *testing.T) {
	assert := assert.New(t)
	tracker := NewTracker()

	// Assuming "/nonexistent" directory does not exist
	filePath := "/nonexistent/all_defers_test.csv"
	err := tracker.WriteAllDefersToCSV(filePath)
	assert.Error(err, "Writing all defers to CSV in a non-existent directory should produce an error")
}
