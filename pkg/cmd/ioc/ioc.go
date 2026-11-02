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
	"github.com/crowdstrike/falcon-cli/pkg/factory"
	"github.com/spf13/cobra"
	"k8s.io/kubectl/pkg/util/templates"
)

// NewIOCCmd represents the ioc command group.
func NewIOCCmd(f *factory.Factory) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ioc",
		Short: "Query and manage custom indicators of compromise (IOCs)",
		Long: templates.LongDesc(`Query and manage custom indicators of compromise (IOCs).

            List and inspect custom IOCs, and create or delete them. Create and
            delete are mutating actions gated behind --confirm.`),
		Example: templates.Examples(`
            # List IOCs
            falcon ioc list

            # Filter to domain-type IOCs
            falcon ioc list --filter "type:'domain'"

            # Get specific IOCs by ID
            falcon ioc get --ids <id1>,<id2>

            # Create an IOC (gated behind --confirm)
            falcon ioc create --value evil.example.com --type domain --action detect --severity high --confirm

            # Delete IOCs (gated behind --confirm)
            falcon ioc delete --ids <id1>,<id2> --confirm
        `),
	}

	cmd.AddCommand(NewCmdList(f))
	cmd.AddCommand(NewCmdGet(f))
	cmd.AddCommand(NewCmdCreate(f))
	cmd.AddCommand(NewCmdDelete(f))
	return cmd
}
