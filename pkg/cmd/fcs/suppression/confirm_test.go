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

package suppression

import (
	"errors"
	"testing"

	"github.com/crowdstrike/falcon-cli/internal/testutil"
	"github.com/crowdstrike/gofalcon/falcon/client"
)

// Without --confirm a write must print a plan and never create a real client.
func TestDelete_DryRunByDefault(t *testing.T) {
	f, buf := testutil.FactoryWithBuffer()
	f.FalconClient = func() (*client.CrowdStrikeAPISpecification, error) {
		t.Fatal("dry run must not create a real Falcon client")
		return nil, errors.New("unreachable")
	}
	cmd := NewCmdDelete(f)
	cmd.SetArgs([]string{"--ids", "r-1"})
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("dry run errored: %v", err)
	}
	if !testutil.ContainsAll(buf.String(), "\"dry_run\": true", "DELETE", "r-1") {
		t.Fatalf("unexpected dry-run output: %s", buf.String())
	}
}

// With --confirm the real client is used.
func TestDelete_ConfirmUsesRealClient(t *testing.T) {
	f, buf := testutil.FactoryWithBuffer()
	called := false
	f.FalconClient = func() (*client.CrowdStrikeAPISpecification, error) {
		called = true
		return nil, errors.New("no creds in test")
	}
	cmd := NewCmdDelete(f)
	cmd.SetArgs([]string{"--ids", "r-1", "--confirm"})
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	_ = cmd.Execute()
	if !called {
		t.Fatal("--confirm must create the real client")
	}
}
