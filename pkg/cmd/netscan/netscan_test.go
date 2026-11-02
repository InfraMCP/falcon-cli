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

package netscan

import (
	"testing"

	"github.com/crowdstrike/falcon-cli/internal/testutil"
	"github.com/crowdstrike/falcon-cli/pkg/factory"
)

func TestNewNetscanCmd_Wiring(t *testing.T) {
	cmd := NewNetscanCmd(&factory.Factory{})
	testutil.AssertHasSubcommands(t, testutil.SubcommandNames(cmd),
		[]string{"networks", "scans", "zones", "scanners", "templates", "scan-runs"})
}

func TestNetscanNetworks_CRUDWiring(t *testing.T) {
	networks := testutil.FindSub(NewNetscanCmd(&factory.Factory{}), "networks")
	if networks == nil {
		t.Fatal("networks subcommand missing")
	}
	testutil.AssertHasSubcommands(t, testutil.SubcommandNames(networks),
		[]string{"list", "get", "create", "update", "delete"})
}

func TestNetscanNetworksCreate_DryRunByDefault(t *testing.T) {
	f, buf := testutil.FactoryWithBuffer()
	root := NewNetscanCmd(f)
	root.SetArgs([]string{"networks", "create", "--name", "Core DC", "--subnet", "10.20.0.0/24", "--scanner-assignment-type", "zone", "--zone-id", "z1"})
	root.SetOut(buf)
	root.SetErr(buf)
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute: %v\n%s", err, buf.String())
	}
	out := buf.String()
	if !testutil.ContainsAll(out, `"dry_run": true`, "10.20.0.0/24", "Core DC") {
		t.Errorf("networks create dry-run missing expected fields:\n%s", out)
	}
}

func TestNetscanScanners_ReadOnly(t *testing.T) {
	// scanners is a read-only resource: no create/update/delete.
	scanners := testutil.FindSub(NewNetscanCmd(&factory.Factory{}), "scanners")
	if scanners == nil {
		t.Fatal("scanners subcommand missing")
	}
	for _, forbidden := range []string{"create", "update", "delete"} {
		if testutil.FindSub(scanners, forbidden) != nil {
			t.Errorf("scanners unexpectedly exposes %q (should be read-only)", forbidden)
		}
	}
}
