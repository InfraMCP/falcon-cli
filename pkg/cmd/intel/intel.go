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
	"github.com/crowdstrike/falcon-cli/pkg/factory"
	"github.com/spf13/cobra"
	"k8s.io/kubectl/pkg/util/templates"
)

// NewIntelCmd represents the intel command group.
func NewIntelCmd(f *factory.Factory) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "intel",
		Short: "Query CrowdStrike threat intelligence",
		Long: templates.LongDesc(`Query CrowdStrike Falcon threat intelligence.

            List intelligence actors (adversaries), indicators of compromise,
            and finished intelligence reports. All subcommands are read-only and
            accept FQL filters, sorting and pagination.`),
		Example: templates.Examples(`
            # List intel actors (adversaries)
            falcon intel actors list

            # List indicators of compromise
            falcon intel indicators list

            # List finished intelligence reports
            falcon intel reports list
        `),
	}

	cmd.AddCommand(newActorsCmd(f))
	cmd.AddCommand(newIndicatorsCmd(f))
	cmd.AddCommand(newReportsCmd(f))
	return cmd
}
