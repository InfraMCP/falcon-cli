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

package detections

import (
	"testing"

	"github.com/crowdstrike/falcon-cli/internal/testutil"
	"github.com/crowdstrike/falcon-cli/pkg/cmdutil"
	"github.com/crowdstrike/falcon-cli/pkg/factory"
	"github.com/crowdstrike/gofalcon/falcon/models"
)

func TestDetectionTableDef_RowFunc_SeverityNamePreferred(t *testing.T) {
	sev := int64(80)
	row := detectionTableDef.RowFunc(&models.DetectsAlert{
		CompositeID:  cmdutil.Ptr("c1"),
		Severity:     &sev,
		SeverityName: cmdutil.Ptr("High"),
		Status:       cmdutil.Ptr("new"),
		Tactic:       cmdutil.Ptr("Execution"),
		Technique:    cmdutil.Ptr("PowerShell"),
		Device:       &models.DetectsAlertDevice{Hostname: "host9"},
	})
	// SeverityName ("High") overrides the numeric severity in the column.
	want := []string{"c1", "High", "new", "Execution", "PowerShell", "", "host9"}
	testutil.AssertRow(t, row, want)
}

func TestDetectionTableDef_RowFunc_NumericSeverityWhenNoName(t *testing.T) {
	sev := int64(50)
	row := detectionTableDef.RowFunc(&models.DetectsAlert{
		CompositeID: cmdutil.Ptr("c2"),
		Severity:    &sev,
	})
	if row[1] != "50" {
		t.Errorf("severity column = %q, want 50", row[1])
	}
}

func TestDetectionTableDef_RowFunc_WrongType(t *testing.T) {
	if row := detectionTableDef.RowFunc(42); row != nil {
		t.Errorf("RowFunc on wrong type = %v, want nil", row)
	}
}

func TestNewDetectionsCmd_Wiring(t *testing.T) {
	cmd := NewDetectionsCmd(&factory.Factory{})
	testutil.AssertHasSubcommands(t, testutil.SubcommandNames(cmd), []string{"list", "get", "aggregate"})
}
