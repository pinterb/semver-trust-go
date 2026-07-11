// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"io"
)

// errWriter threads the first write error through a sequence of formatted
// writes, so multi-line command output reads as a straight-line report rather
// than an error check after every line; the first failure short-circuits the
// rest. Same pattern as internal/verify's renderer.
type errWriter struct {
	w   io.Writer
	err error
}

func (e *errWriter) printf(format string, a ...any) {
	if e.err != nil {
		return
	}
	_, e.err = fmt.Fprintf(e.w, format, a...)
}

func (e *errWriter) println(a ...any) {
	if e.err != nil {
		return
	}
	_, e.err = fmt.Fprintln(e.w, a...)
}
