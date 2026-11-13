package main

import (
	"golang.org/x/term"
	"os"
	"runtime"
)

type terminalInput struct {
	*os.File
	state  *term.State
	closed bool
}

func (t *terminalInput) Close() error {
	if t.closed {
		return nil
	}
	t.closed = true
	term.Restore(int(t.Fd()), t.state)
	return t.File.Close()
}
func confirmationTerminal() (*terminalInput, error) {
	name := "/dev/tty"
	if runtime.GOOS == "windows" {
		name = "CONIN$"
	}
	f, e := os.OpenFile(name, os.O_RDWR, 0)
	if e != nil {
		return nil, e
	}
	state, e := term.MakeRaw(int(f.Fd()))
	if e != nil {
		f.Close()
		return nil, e
	}
	return &terminalInput{File: f, state: state}, nil
}
