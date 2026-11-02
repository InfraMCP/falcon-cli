// Copyright (c) 2026 CrowdStrike, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// Package testutil provides shared helpers for command-group unit tests:
// a factory wired to an in-memory output buffer, and small assertions for
// table rows and cobra command wiring. Keeping them here avoids duplicating
// the same helpers across every pkg/cmd/<group> test file.
package testutil

import (
	"bytes"
	"strings"
	"testing"

	"github.com/crowdstrike/falcon-cli/pkg/factory"
	"github.com/crowdstrike/falcon-cli/pkg/iostreams"
	"github.com/spf13/cobra"
)

// FactoryWithBuffer returns a Factory whose IOStreams.Out is the returned
// buffer, so a command's printed output can be asserted. FalconClient is left
// nil: callers must only exercise paths that do not reach the API (for example
// a dry-run write without --confirm).
func FactoryWithBuffer() (*factory.Factory, *bytes.Buffer) {
	buf := &bytes.Buffer{}
	io := &iostreams.IOStreams{In: nil, Out: buf, ErrOut: buf}
	return &factory.Factory{IOStreams: io}, buf
}

// SubcommandNames returns the Use names of a command's immediate subcommands.
func SubcommandNames(cmd *cobra.Command) []string {
	var names []string
	for _, c := range cmd.Commands() {
		names = append(names, c.Name())
	}
	return names
}

// FindSub returns the immediate subcommand with the given name, or nil.
func FindSub(cmd *cobra.Command, name string) *cobra.Command {
	for _, c := range cmd.Commands() {
		if c.Name() == name {
			return c
		}
	}
	return nil
}

// AssertHasSubcommands fails if any wanted subcommand name is missing.
func AssertHasSubcommands(t *testing.T, got, want []string) {
	t.Helper()
	set := make(map[string]bool, len(got))
	for _, g := range got {
		set[g] = true
	}
	for _, w := range want {
		if !set[w] {
			t.Errorf("missing subcommand %q; have %v", w, got)
		}
	}
}

// AssertRow fails if got does not equal want element-for-element.
func AssertRow(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("row length = %d, want %d\n got: %v\nwant: %v", len(got), len(want), got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("row[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// ContainsAll reports whether s contains every substring.
func ContainsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		if !strings.Contains(s, sub) {
			return false
		}
	}
	return true
}

// RunSub executes root with the given args (e.g. "contain", "--ids", "x") and
// returns combined stdout/stderr captured from the buffer the factory writes
// to. It fails the test on a non-nil execution error, so it is for paths
// expected to succeed (such as a dry-run).
func RunSub(t *testing.T, root *cobra.Command, buf *bytes.Buffer, args ...string) string {
	t.Helper()
	root.SetArgs(args)
	root.SetOut(buf)
	root.SetErr(buf)
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute(%v): %v\noutput:\n%s", args, err, buf.String())
	}
	return buf.String()
}
