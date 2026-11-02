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
	"github.com/crowdstrike/falcon-cli/pkg/factory"
	"github.com/spf13/cobra"
	"k8s.io/kubectl/pkg/util/templates"
)

// NewDetectionsCmd represents the detections command group.
func NewDetectionsCmd(f *factory.Factory) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "detections",
		Short: "Query and inspect detections (alerts)",
		Long: templates.LongDesc(`Query and inspect detections (alerts) in your Falcon tenant.

            List alerts matching a Falcon Query Language (FQL) filter and fetch
            full detail for specific alerts by composite ID. The alerts API
            backs the Falcon detections experience, exposing severity, status,
            and MITRE ATT&CK tactic/technique context per alert.`),
		Example: templates.Examples(`
            # List recent alerts
            falcon detections list

            # Filter to high-severity new alerts
            falcon detections list --filter "severity:>=70+status:'new'"

            # Get full detail for specific alerts by composite ID
            falcon detections get --ids <composite_id1>,<composite_id2>

            # Aggregate alert counts by status
            falcon detections aggregate --field status
        `),
	}

	cmd.AddCommand(NewCmdList(f))
	cmd.AddCommand(NewCmdGet(f))
	cmd.AddCommand(NewCmdAggregate(f))
	return cmd
}
