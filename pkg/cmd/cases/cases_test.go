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

package cases

import (
	"errors"
	"testing"

	"github.com/crowdstrike/falcon-cli/internal/testutil"
	"github.com/crowdstrike/falcon-cli/pkg/cmdutil"
	"github.com/crowdstrike/falcon-cli/pkg/factory"
	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/models"
)

func TestWiring(t *testing.T) {
	cmd := NewCasesCmd(&factory.Factory{})
	testutil.AssertHasSubcommands(t, testutil.SubcommandNames(cmd),
		[]string{"list", "get", "create", "update", "comment", "assign", "evidence"})
}

func TestCaseTableDef_RowFunc(t *testing.T) {
	row := caseTableDef.RowFunc(&models.SdkCaseVM{
		ID:           cmdutil.Ptr("c-1"),
		Name:         cmdutil.Ptr("triage"),
		Status:       cmdutil.Ptr("New"),
		SeverityInfo: &models.SdkCaseSeverityInfoVM{Level: cmdutil.Ptr("High")},
		AssignedTo:   &models.SdkFalconUserVM{FullName: cmdutil.Ptr("Jo Example")},
	})
	if row[0] != "c-1" || row[2] != "High" || row[3] != "New" || row[4] != "Jo Example" {
		t.Fatalf("row = %v", row)
	}
}

func TestCaseTableDef_RowFunc_AssigneeFallsBackToEmail(t *testing.T) {
	row := caseTableDef.RowFunc(&models.SdkCaseVM{
		ID:         cmdutil.Ptr("c-2"),
		AssignedTo: &models.SdkFalconUserVM{Email: cmdutil.Ptr("jo@example.com")},
	})
	if row[4] != "jo@example.com" {
		t.Fatalf("assignee = %q", row[4])
	}
}

func TestCreate_InvalidSeverity(t *testing.T) {
	f, buf := testutil.FactoryWithBuffer()
	root := NewCasesCmd(f)
	root.SetArgs([]string{"create", "--name", "x", "--description", "y", "--severity", "bogus"})
	root.SetOut(buf)
	root.SetErr(buf)
	if err := root.Execute(); err == nil || !testutil.ContainsAll(err.Error(), "invalid --severity") {
		t.Fatalf("want invalid severity error, got %v", err)
	}
}

func TestCreate_DryRunByDefault(t *testing.T) {
	f, buf := testutil.FactoryWithBuffer()
	f.FalconClient = func() (*client.CrowdStrikeAPISpecification, error) {
		t.Fatal("dry-run create must not build a real client")
		return nil, errors.New("unreachable")
	}
	root := NewCasesCmd(f)
	root.SetArgs([]string{"create", "--name", "triage", "--description", "body", "--severity", "high", "--assignee", "u-1"})
	root.SetOut(buf)
	root.SetErr(buf)
	if err := root.Execute(); err != nil {
		t.Fatalf("dry run errored: %v", err)
	}
	if !testutil.ContainsAll(buf.String(), "\"dry_run\": true", "PUT", "triage") {
		t.Fatalf("unexpected dry-run output: %s", buf.String())
	}
}

func TestUpdate_NothingToChange(t *testing.T) {
	f, buf := testutil.FactoryWithBuffer()
	root := NewCasesCmd(f)
	root.SetArgs([]string{"update", "--id", "c-1"})
	root.SetOut(buf)
	root.SetErr(buf)
	if err := root.Execute(); err == nil || !testutil.ContainsAll(err.Error(), "nothing to update") {
		t.Fatalf("want nothing-to-update error, got %v", err)
	}
}

func TestAssign_DryRunByDefault(t *testing.T) {
	f, buf := testutil.FactoryWithBuffer()
	f.FalconClient = func() (*client.CrowdStrikeAPISpecification, error) {
		t.Fatal("dry-run assign must not build a real client")
		return nil, errors.New("unreachable")
	}
	root := NewCasesCmd(f)
	root.SetArgs([]string{"assign", "--id", "c-1", "--assignee", "u-9"})
	root.SetOut(buf)
	root.SetErr(buf)
	if err := root.Execute(); err != nil {
		t.Fatalf("dry run errored: %v", err)
	}
	if !testutil.ContainsAll(buf.String(), "\"dry_run\": true", "PATCH") {
		t.Fatalf("unexpected dry-run output: %s", buf.String())
	}
}
