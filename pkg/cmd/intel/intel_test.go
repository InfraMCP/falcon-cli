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

package intel

import (
	"bytes"
	"testing"

	"github.com/crowdstrike/falcon-cli/internal/testutil"
	"github.com/crowdstrike/falcon-cli/pkg/cmdutil"
	"github.com/crowdstrike/falcon-cli/pkg/factory"
	"github.com/crowdstrike/falcon-cli/pkg/output"
	"github.com/crowdstrike/gofalcon/falcon/models"
)

func TestIndicatorTableDef_RowFunc(t *testing.T) {
	row := indicatorTableDef.RowFunc(&models.DomainPublicIndicatorV3{
		ID:        cmdutil.Ptr("id1"),
		Indicator: cmdutil.Ptr("evil.com"),
		Type:      cmdutil.Ptr("domain"),
	})
	testutil.AssertRow(t, row, []string{"id1", "evil.com", "domain"})
}

func TestActorTableDef_RowFunc_FormatsInt64Fields(t *testing.T) {
	id := int64(42)
	last := int64(1730000000)
	row := actorTableDef.RowFunc(&models.ActorActorDocument{
		ID:               &id,
		Name:             "FANCY BEAR",
		Slug:             "fancy-bear",
		LastActivityDate: &last,
	})
	testutil.AssertRow(t, row, []string{"42", "FANCY BEAR", "fancy-bear", "1730000000"})
}

func TestReportTableDef_RowFunc_WrongType(t *testing.T) {
	if row := reportTableDef.RowFunc("x"); row != nil {
		t.Errorf("RowFunc on wrong type = %v, want nil", row)
	}
}

func TestNewIntelCmd_Wiring(t *testing.T) {
	cmd := NewIntelCmd(&factory.Factory{})
	testutil.AssertHasSubcommands(t, testutil.SubcommandNames(cmd), []string{"actors", "indicators", "reports"})
	// Each resource group exposes a `list` subcommand.
	for _, group := range []string{"actors", "indicators", "reports"} {
		sub := testutil.FindSub(cmd, group)
		if sub == nil || testutil.FindSub(sub, "list") == nil {
			t.Errorf("intel %s is missing its list subcommand", group)
		}
	}
}

// TestNewListCmd_SharedHelper exercises the generic helper directly: it should
// run the supplied query closure and print the rows via the given table def.
func TestNewListCmd_SharedHelper(t *testing.T) {
	f, buf := testutil.FactoryWithBuffer()
	called := false
	cmd := newListCmd(
		f, "short", "long", "example", indicatorTableDef,
		func(_ *listOptions) ([]*models.DomainPublicIndicatorV3, error) {
			called = true
			return []*models.DomainPublicIndicatorV3{
				{ID: cmdutil.Ptr("i1"), Indicator: cmdutil.Ptr("bad.example"), Type: cmdutil.Ptr("domain")},
			}, nil
		},
	)
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"--output", string(output.FormatJSON)})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !called {
		t.Error("query closure was not called")
	}
	if !bytes.Contains(buf.Bytes(), []byte("bad.example")) {
		t.Errorf("rendered output missing the indicator value:\n%s", buf.String())
	}
}
