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

package spotlight

import (
	"testing"

	"github.com/crowdstrike/falcon-cli/internal/testutil"
	"github.com/crowdstrike/falcon-cli/pkg/cmdutil"
	"github.com/crowdstrike/falcon-cli/pkg/factory"
	"github.com/crowdstrike/gofalcon/falcon/models"
)

func TestVulnerabilityTableDef_RowFunc(t *testing.T) {
	row := vulnerabilityTableDef.RowFunc(&models.DomainBaseAPIVulnerabilityV2{
		Cve: &models.DomainAPIVulnerabilityCVEDetailsFacetV2{
			ID:          cmdutil.Ptr("CVE-2026-1"),
			Severity:    "CRITICAL",
			ExprtRating: "HIGH",
			BaseScore:   9.8,
		},
		HostInfo:         &models.DomainAPIVulnerabilityHostFacetV2{Hostname: cmdutil.Ptr("db01")},
		Status:           cmdutil.Ptr("open"),
		Aid:              cmdutil.Ptr("aid-7"),
		CreatedTimestamp: cmdutil.Ptr("2026-10-01"),
	})
	want := []string{"CVE-2026-1", "CRITICAL", "9.8", "HIGH", "open", "db01", "aid-7", "2026-10-01"}
	testutil.AssertRow(t, row, want)
}

func TestVulnerabilityTableDef_RowFunc_NilFacets(t *testing.T) {
	// Nil Cve/HostInfo must not panic; those columns come back empty.
	row := vulnerabilityTableDef.RowFunc(&models.DomainBaseAPIVulnerabilityV2{
		Status: cmdutil.Ptr("closed"),
	})
	if row[0] != "" || row[5] != "" || row[4] != "closed" {
		t.Errorf("unexpected row with nil facets: %v", row)
	}
}

func TestVulnerabilityTableDef_RowFunc_WrongType(t *testing.T) {
	if row := vulnerabilityTableDef.RowFunc(nil); row != nil {
		t.Errorf("RowFunc on nil = %v, want nil", row)
	}
}

func TestNewSpotlightCmd_Wiring(t *testing.T) {
	cmd := NewSpotlightCmd(&factory.Factory{})
	testutil.AssertHasSubcommands(t, testutil.SubcommandNames(cmd), []string{"vulnerabilities"})
}

func TestVulnerabilitiesList_RequiresFilter(t *testing.T) {
	// Without --filter the command must fail fast with a helpful message and
	// never reach the API (so a nil FalconClient is never called).
	f, buf := testutil.FactoryWithBuffer()
	root := NewSpotlightCmd(f)
	root.SetArgs([]string{"vulnerabilities", "list"})
	root.SetOut(buf)
	root.SetErr(buf)
	err := root.Execute()
	if err == nil {
		t.Fatal("expected an error when --filter is omitted, got nil")
	}
	if !testutil.ContainsAll(err.Error(), "filter is required") {
		t.Errorf("error should explain the filter requirement, got: %v", err)
	}
}
