package main

import (
	"io"
	"os"
)

// rowsFile is the -o file of run, with the first write error kept so a full
// disk fails the run at its end and does not stop the rows on stdout.
type rowsFile struct {
	f   *os.File
	err error
}

// openRunOut creates the file run -o writes its rows to, before the run
// starts, so a path that cannot be written fails at once.
func openRunOut(path string) (*rowsFile, error) {
	if st, err := os.Stat(path); err == nil && st.IsDir() {
		return nil, usagef("-o %s is a directory: -o names the file the rows are written to", path)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return nil, err
	}
	return &rowsFile{f: f}, nil
}

func (r *rowsFile) Write(p []byte) (int, error) {
	if r.err == nil {
		_, r.err = r.f.Write(p)
	}
	return len(p), nil
}

// close closes the file and says the first thing that went wrong with it.
func (r *rowsFile) close() error {
	if err := r.f.Close(); r.err == nil {
		r.err = err
	}
	return r.err
}

// runSink is where run writes its rows: stdout unless -quiet or a command
// built on run owns it, and the -o file. nil when neither takes them.
func runSink(stdout bool, f *rowsFile) io.Writer {
	switch {
	case stdout && f != nil:
		return io.MultiWriter(os.Stdout, f)
	case stdout:
		return os.Stdout
	case f != nil:
		return f
	}
	return nil
}
