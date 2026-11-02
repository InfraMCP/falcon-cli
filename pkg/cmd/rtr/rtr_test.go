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

package rtr

import (
	"testing"

	"github.com/crowdstrike/falcon-cli/internal/testutil"
	"github.com/crowdstrike/falcon-cli/pkg/factory"
)

func TestSessionsTableDef_RowFunc(t *testing.T) {
	row := sessionsTableDef.RowFunc(sessionIDRow{SessionID: "sess-1"})
	testutil.AssertRow(t, row, []string{"sess-1"})
}

func TestSessionsTableDef_RowFunc_WrongType(t *testing.T) {
	if row := sessionsTableDef.RowFunc("sess-1"); row != nil {
		t.Errorf("RowFunc on wrong type = %v, want nil", row)
	}
}

func TestNewRTRCmd_Wiring_ReadOnly(t *testing.T) {
	cmd := NewRTRCmd(&factory.Factory{})
	sessions := testutil.FindSub(cmd, "sessions")
	if sessions == nil {
		t.Fatal("rtr is missing the sessions subcommand")
	}
	if testutil.FindSub(sessions, "list") == nil {
		t.Error("rtr sessions is missing list")
	}
	// RTR is deliberately read-only: no command-execution verbs.
	for _, forbidden := range []string{"run", "execute", "exec", "command"} {
		if testutil.FindSub(sessions, forbidden) != nil {
			t.Errorf("rtr sessions unexpectedly exposes a %q subcommand (should be read-only)", forbidden)
		}
	}
}
