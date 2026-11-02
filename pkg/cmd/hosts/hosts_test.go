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

package hosts

import (
	"testing"

	"github.com/crowdstrike/falcon-cli/internal/testutil"
	"github.com/crowdstrike/falcon-cli/pkg/factory"
	"github.com/crowdstrike/gofalcon/falcon/models"
)

func TestHostTableDef_RowFunc(t *testing.T) {
	id := "aid-123"
	row := hostTableDef.RowFunc(&models.DeviceapiDeviceSwagger{
		DeviceID:        &id,
		Hostname:        "web01",
		ProductTypeDesc: "Server",
		OsVersion:       "Windows 2022",
		Status:          "normal",
		LocalIP:         "10.0.0.5",
		LastSeen:        "2026-11-02T00:00:00Z",
	})
	testutil.AssertRow(t, row, []string{"web01", "aid-123", "Server", "Windows 2022", "normal", "10.0.0.5", "2026-11-02T00:00:00Z"})
}

func TestHostTableDef_RowFunc_WrongType(t *testing.T) {
	if row := hostTableDef.RowFunc("not a host"); row != nil {
		t.Errorf("RowFunc on wrong type = %v, want nil", row)
	}
}

func TestNewHostsCmd_Wiring(t *testing.T) {
	cmd := NewHostsCmd(&factory.Factory{})
	testutil.AssertHasSubcommands(t, testutil.SubcommandNames(cmd),
		[]string{"list", "get", "contain", "lift-containment", "hide", "unhide"})
}

func TestHostsContain_DryRunByDefault(t *testing.T) {
	f, buf := testutil.FactoryWithBuffer()
	out := testutil.RunSub(t, NewHostsCmd(f), buf, "contain", "--ids", "aid-1")
	if !testutil.ContainsAll(out, `"dry_run": true`, `"action": "contain"`, "aid-1") {
		t.Errorf("contain dry-run missing expected fields:\n%s", out)
	}
}

func TestHostsContain_HasConfirmFlag(t *testing.T) {
	cmd := testutil.FindSub(NewHostsCmd(&factory.Factory{}), "contain")
	if cmd == nil || cmd.Flags().Lookup("confirm") == nil {
		t.Fatal("contain command is missing the --confirm flag")
	}
}
