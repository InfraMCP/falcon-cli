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

package netscan

import (
	"github.com/crowdstrike/falcon-cli/pkg/factory"
	"github.com/spf13/cobra"
	"k8s.io/kubectl/pkg/util/templates"
)

// NewNetscanCmd represents the netscan command group.
func NewNetscanCmd(f *factory.Factory) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "netscan",
		Short: "Manage Network Vulnerability Assessment (NVA) resources",
		Long: templates.LongDesc(`Manage CrowdStrike Falcon Network Scan (NVA) resources.

            Configure networks (subnets), scan definitions and zones, and read
            the scanners, templates and scan-runs needed to wire them together.

            These endpoints are not exposed by gofalcon's typed client, so this
            group drives the /netscan/* REST API through the SDK's authenticated
            transport. Output is the raw API payload; prefer --output json.

            Mutating actions (create/update/delete) are gated behind --confirm.
            Without it, the command prints the request it would send and exits.`),
		Example: templates.Examples(`
            # Read-only discovery
            falcon netscan scanners list
            falcon netscan templates list --output json
            falcon netscan networks list --filter "name:*'DC'*"

            # Create a network (dry run, then execute)
            falcon netscan networks create --name "Core DC" --subnet 10.20.0.0/24 \
                --scanner-assignment-type zone --zone-id <zone_id>
            falcon netscan networks create --name "Core DC" --subnet 10.20.0.0/24 \
                --scanner-assignment-type zone --zone-id <zone_id> --confirm

            # Manage zones
            falcon netscan zones create --name "Sydney" --scanner <aid1> --scanner <aid2> --confirm
            falcon netscan zones update --id <id> --add-scanner <aid> --confirm
        `),
	}

	cmd.AddCommand(newNetworksCmd(f))
	cmd.AddCommand(newScansCmd(f))
	cmd.AddCommand(newZonesCmd(f))
	cmd.AddCommand(newScannersCmd(f))
	cmd.AddCommand(newTemplatesCmd(f))
	cmd.AddCommand(newScanRunsCmd(f))
	return cmd
}
