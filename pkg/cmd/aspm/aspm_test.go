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

package aspm

import (
	"testing"

	"github.com/crowdstrike/falcon-cli/internal/testutil"
	"github.com/crowdstrike/falcon-cli/pkg/cmdutil"
	"github.com/crowdstrike/falcon-cli/pkg/factory"
	"github.com/crowdstrike/gofalcon/falcon/models"
)

func TestNewASPMCmd_Wiring(t *testing.T) {
	cmd := NewASPMCmd(&factory.Factory{})
	testutil.AssertHasSubcommands(t, testutil.SubcommandNames(cmd),
		[]string{"findings", "integrations", "integration-types", "services", "tags"})
}

func TestFindingsTableDef_RowFunc(t *testing.T) {
	row := findingsTableDef.RowFunc(&models.AssetsResourceApplicationFindingsItem{
		Crn:         cmdutil.Ptr("crn:aspm:svc/7"),
		FindingType: cmdutil.Ptr("vulnerabilities"),
		Findings: []models.AssetsResourceApplicationFindingsItemFindings{
			map[string]any{"a": 1}, map[string]any{"b": 2},
		},
	})
	testutil.AssertRow(t, row, []string{"crn:aspm:svc/7", "vulnerabilities", "2"})
}

func TestFindingsTableDef_RowFunc_WrongType(t *testing.T) {
	if row := findingsTableDef.RowFunc(nil); row != nil {
		t.Errorf("RowFunc on nil = %v, want nil", row)
	}
}

func TestIntegrationsTableDef_RowFunc(t *testing.T) {
	row := integrationsTableDef.RowFunc(&models.TypesListIntegrationItem{
		ID:              42,
		Name:            "prod-github",
		Enabled:         true,
		IntegrationType: &models.TypesIntegrationType{DisplayName: "GitHub", Name: "github"},
	})
	testutil.AssertRow(t, row, []string{"42", "prod-github", "GitHub", "true"})
}

func TestIntegrationsTableDef_RowFunc_NilType(t *testing.T) {
	row := integrationsTableDef.RowFunc(&models.TypesListIntegrationItem{ID: 1, Name: "x"})
	testutil.AssertRow(t, row, []string{"1", "x", "", "false"})
}

func TestIntegrationTypesTableDef_RowFunc(t *testing.T) {
	row := integrationTypesTableDef.RowFunc(&models.TypesIntegrationType{
		ID:          3,
		Name:        "github",
		DisplayName: "GitHub",
		Configured:  true,
		Enabled:     false,
	})
	testutil.AssertRow(t, row, []string{"3", "github", "GitHub", "true", "false"})
}

func TestFindingsList_RequiresType(t *testing.T) {
	// Without --type the command must fail fast and never reach the API.
	f, buf := testutil.FactoryWithBuffer()
	root := NewASPMCmd(f)
	root.SetArgs([]string{"findings", "list"})
	root.SetOut(buf)
	root.SetErr(buf)
	if err := root.Execute(); err == nil {
		t.Fatal("expected an error when --type is omitted, got nil")
	}
}
