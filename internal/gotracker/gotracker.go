package gotracker

import (
	"encoding/csv"
	"fmt"
	"os"
	"sync"
)

type GoroutineTracker interface {
	TrackGoroutine(funcName string, params ...interface{})
	TrackDeferCall(funcName string, params ...interface{})
	ActiveGoroutines() []string
	AreAllGoroutinesClosed() bool
	WriteActiveGoroutinesToCSV(filePath string) error
	WriteAllGoroutinesToCSV(filePath string) error
	WriteAllDefersToCSV(filePath string) error
}

type tracker struct {
	mu               sync.Mutex
	activeGoroutines map[string]int
	allGoroutines    map[string]int
	allDefers        map[string]int
}

func NewTracker() GoroutineTracker {
	return &tracker{
		activeGoroutines: make(map[string]int),
		allGoroutines:    make(map[string]int),
		allDefers:        make(map[string]int),
	}
}

func (t *tracker) TrackGoroutine(funcName string, params ...interface{}) {
	t.mu.Lock()
	defer t.mu.Unlock()

	key := fmt.Sprintf("%s(%v)", funcName, params)
	t.activeGoroutines[key]++
	t.allGoroutines[key]++
}

func (t *tracker) TrackDeferCall(funcName string, params ...interface{}) {
	t.mu.Lock()
	defer t.mu.Unlock()

	key := fmt.Sprintf("%s(%v)", funcName, params)
	t.activeGoroutines[key]--
	t.allDefers[key]++
	if t.activeGoroutines[key] == 0 {
		delete(t.activeGoroutines, key)
	}
}

func (t *tracker) ActiveGoroutines() []string {
	t.mu.Lock()
	defer t.mu.Unlock()

	var active []string
	for key, count := range t.activeGoroutines {
		if count > 0 {
			active = append(active, key)
		}
	}
	return active
}

func (t *tracker) AreAllGoroutinesClosed() bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	for key, count := range t.allGoroutines {
		if count != t.allDefers[key] {
			return false
		}
	}
	return true
}

func (t *tracker) WriteActiveGoroutinesToCSV(filePath string) error {
	return t.writeToCSV(filePath, t.ActiveGoroutines())
}

func (t *tracker) WriteAllGoroutinesToCSV(filePath string) error {
	return t.writeMapToCSV(filePath, t.allGoroutines)
}

func (t *tracker) WriteAllDefersToCSV(filePath string) error {
	return t.writeMapToCSV(filePath, t.allDefers)
}

func (t *tracker) writeToCSV(filePath string, data []string) error {
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	for _, record := range data {
		if err := writer.Write([]string{record}); err != nil {
			return err
		}
	}
	return nil
}

func (t *tracker) writeMapToCSV(filePath string, data map[string]int) error {
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	for key, count := range data {
		record := []string{key, fmt.Sprintf("%d", count)}
		if err := writer.Write(record); err != nil {
			return err
		}
	}
	return nil
}
