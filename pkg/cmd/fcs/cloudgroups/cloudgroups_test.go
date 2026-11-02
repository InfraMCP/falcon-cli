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

package cloudgroups

import (
	"testing"

	"github.com/crowdstrike/falcon-cli/internal/testutil"
	"github.com/crowdstrike/falcon-cli/pkg/factory"
)

func TestNewCloudGroupsCmd_Wiring(t *testing.T) {
	cmd := NewCloudGroupsCmd(&factory.Factory{})
	testutil.AssertHasSubcommands(t, testutil.SubcommandNames(cmd),
		[]string{"list", "get", "create", "update", "delete"})
}

func TestCloudGroupsWrites_HaveConfirmFlag(t *testing.T) {
	cmd := NewCloudGroupsCmd(&factory.Factory{})
	for _, name := range []string{"create", "update", "delete"} {
		sub := testutil.FindSub(cmd, name)
		if sub == nil || sub.Flags().Lookup("confirm") == nil {
			t.Errorf("%s is missing the --confirm flag", name)
		}
	}
}

func TestCloudGroupsDelete_DryRunByDefault(t *testing.T) {
	f, buf := testutil.FactoryWithBuffer()
	root := NewCloudGroupsCmd(f)
	root.SetArgs([]string{"delete", "--ids", "grp-1"})
	root.SetOut(buf)
	root.SetErr(buf)
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute: %v\n%s", err, buf.String())
	}
	if !testutil.ContainsAll(buf.String(), `"dry_run": true`, "grp-1") {
		t.Errorf("cloud-groups delete dry-run missing expected fields:\n%s", buf.String())
	}
}
