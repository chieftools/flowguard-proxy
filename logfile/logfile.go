// Package logfile writes FlowGuard's process log to a size-capped file, for
// hosts where no journal collects stderr, such as SysV init.
package logfile

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"sync"
)

const (
	// DefaultMaxBytes caps the active log file.
	DefaultMaxBytes = 10 << 20
	// DefaultBackups is how many rotated files (flowguard.log.1 …) are kept.
	DefaultBackups = 3
)

// Setup points the standard logger at a rotating file at path. The caller
// reopens it on SIGHUP and closes it on exit.
func Setup(path string) (*RotatingFile, error) {
	file, err := OpenRotatingFile(path, DefaultMaxBytes, DefaultBackups)
	if err != nil {
		return nil, err
	}
	log.SetOutput(file)
	return file, nil
}

// RotatingFile is an io.Writer that renames the file to path.1 (shifting
// older backups up) once a write would push it past maxBytes.
type RotatingFile struct {
	path     string
	maxBytes int64
	backups  int

	mu   sync.Mutex
	file *os.File
	size int64
}

var _ io.WriteCloser = (*RotatingFile)(nil)

// OpenRotatingFile opens or creates path for appending.
func OpenRotatingFile(path string, maxBytes int64, backups int) (*RotatingFile, error) {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes
	}
	if backups < 0 {
		backups = 0
	}
	writer := &RotatingFile{path: path, maxBytes: maxBytes, backups: backups}
	if err := writer.open(); err != nil {
		return nil, err
	}
	return writer, nil
}

func (writer *RotatingFile) open() error {
	if err := os.MkdirAll(filepath.Dir(writer.path), 0o750); err != nil {
		return fmt.Errorf("create log directory: %w", err)
	}
	file, err := os.OpenFile(writer.path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o640)
	if err != nil {
		return fmt.Errorf("open log file: %w", err)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return fmt.Errorf("stat log file: %w", err)
	}
	writer.file = file
	writer.size = info.Size()
	return nil
}

// Write appends p, rotating first when it would exceed the size cap. A
// single record larger than the cap is still written whole.
func (writer *RotatingFile) Write(p []byte) (int, error) {
	writer.mu.Lock()
	defer writer.mu.Unlock()

	if writer.file == nil {
		if err := writer.open(); err != nil {
			return 0, err
		}
	}
	if writer.size > 0 && writer.size+int64(len(p)) > writer.maxBytes {
		if err := writer.rotate(); err != nil {
			// Keep logging into the oversized file rather than losing lines.
			fmt.Fprintf(os.Stderr, "flowguard: rotate %s: %v\n", writer.path, err)
		}
	}
	n, err := writer.file.Write(p)
	writer.size += int64(n)
	return n, err
}

func (writer *RotatingFile) rotate() error {
	if err := writer.file.Close(); err != nil {
		return err
	}
	writer.file = nil

	if writer.backups == 0 {
		if err := os.Remove(writer.path); err != nil && !os.IsNotExist(err) {
			return err
		}
	} else {
		_ = os.Remove(writer.backupPath(writer.backups))
		for index := writer.backups - 1; index >= 1; index-- {
			if err := os.Rename(writer.backupPath(index), writer.backupPath(index+1)); err != nil && !os.IsNotExist(err) {
				return err
			}
		}
		if err := os.Rename(writer.path, writer.backupPath(1)); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return writer.open()
}

func (writer *RotatingFile) backupPath(index int) string {
	return writer.path + "." + strconv.Itoa(index)
}

// Reopen closes and reopens the file, for external rotation (logrotate's
// copytruncate is not needed: send SIGHUP after moving the file).
func (writer *RotatingFile) Reopen() error {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	if writer.file != nil {
		_ = writer.file.Close()
		writer.file = nil
	}
	return writer.open()
}

// Close closes the file.
func (writer *RotatingFile) Close() error {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	if writer.file == nil {
		return nil
	}
	err := writer.file.Close()
	writer.file = nil
	return err
}
