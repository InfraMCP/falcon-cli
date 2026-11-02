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

package ioc

import (
	"testing"

	"github.com/crowdstrike/falcon-cli/internal/testutil"
	"github.com/crowdstrike/falcon-cli/pkg/factory"
	"github.com/crowdstrike/gofalcon/falcon/models"
)

func TestIOCTableDef_RowFunc(t *testing.T) {
	row := iocTableDef.RowFunc(&models.APIIndicatorV1{
		Value:    "1.2.3.4",
		Type:     "ipv4",
		Action:   "detect",
		Severity: "high",
	})
	// Columns: VALUE, TYPE, ACTION, SEVERITY, EXPIRATION (expiration zero -> "").
	if row[0] != "1.2.3.4" || row[1] != "ipv4" || row[2] != "detect" || row[3] != "high" {
		t.Errorf("unexpected row: %v", row)
	}
}

func TestIOCTableDef_RowFunc_WrongType(t *testing.T) {
	if row := iocTableDef.RowFunc(struct{}{}); row != nil {
		t.Errorf("RowFunc on wrong type = %v, want nil", row)
	}
}

func TestNewIOCCmd_Wiring(t *testing.T) {
	cmd := NewIOCCmd(&factory.Factory{})
	testutil.AssertHasSubcommands(t, testutil.SubcommandNames(cmd), []string{"list", "get", "create", "delete"})
}

func TestIOCCreate_DryRunByDefault(t *testing.T) {
	f, buf := testutil.FactoryWithBuffer()
	out := testutil.RunSub(t, NewIOCCmd(f), buf, "create", "--value", "9.9.9.9", "--type", "ipv4", "--action", "detect")
	if !testutil.ContainsAll(out, `"dry_run": true`, `"action": "create"`, "9.9.9.9") {
		t.Errorf("ioc create dry-run missing expected fields:\n%s", out)
	}
}

func TestIOCDelete_DryRunByDefault(t *testing.T) {
	f, buf := testutil.FactoryWithBuffer()
	out := testutil.RunSub(t, NewIOCCmd(f), buf, "delete", "--ids", "ioc-1")
	if !testutil.ContainsAll(out, `"dry_run": true`, "ioc-1") {
		t.Errorf("ioc delete dry-run missing expected fields:\n%s", out)
	}
}

func TestIOCWrites_HaveConfirmFlag(t *testing.T) {
	cmd := NewIOCCmd(&factory.Factory{})
	for _, name := range []string{"create", "delete"} {
		sub := testutil.FindSub(cmd, name)
		if sub == nil || sub.Flags().Lookup("confirm") == nil {
			t.Errorf("%s is missing the --confirm flag", name)
		}
	}
}
