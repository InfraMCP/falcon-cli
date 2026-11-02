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
	"github.com/crowdstrike/falcon-cli/pkg/factory"
	"github.com/spf13/cobra"
	"k8s.io/kubectl/pkg/util/templates"
)

// NewHostsCmd represents the hosts command group.
func NewHostsCmd(f *factory.Factory) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "hosts",
		Short: "Query and manage hosts (devices)",
		Long: templates.LongDesc(`Query and manage hosts (devices) in your Falcon tenant.

            List and inspect devices, and contain or lift containment on a host
            during incident response. Containment actions are gated behind
            --confirm.`),
		Example: templates.Examples(`
            # List hosts
            falcon hosts list

            # Filter to Windows hosts seen in the last day
            falcon hosts list --filter "platform_name:'Windows'"

            # Get full detail for specific hosts
            falcon hosts get --ids <aid1>,<aid2>

            # Network-contain a host (gated behind --confirm)
            falcon hosts contain --ids <aid> --confirm
        `),
	}

	cmd.AddCommand(NewCmdList(f))
	cmd.AddCommand(NewCmdGet(f))
	cmd.AddCommand(NewCmdAction(f, "contain", "Network-contain hosts", "contain"))
	cmd.AddCommand(NewCmdAction(f, "lift-containment", "Lift network containment on hosts", "lift_containment"))
	cmd.AddCommand(NewCmdAction(f, "hide", "Hide hosts from the console", "hide_host"))
	cmd.AddCommand(NewCmdAction(f, "unhide", "Restore hidden hosts", "unhide_host"))
	return cmd
}
