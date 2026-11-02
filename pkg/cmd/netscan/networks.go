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
	"github.com/crowdstrike/falcon-cli/pkg/cmdutil"
	"github.com/crowdstrike/falcon-cli/pkg/factory"
	"github.com/spf13/cobra"
	"k8s.io/kubectl/pkg/util/templates"
)

const (
	networksEntity = "/netscan/entities/networks/v1"
	networksQuery  = "/netscan/queries/networks/v1"
)

// newNetworksCmd builds the "networks" subcommand group (subnets).
func newNetworksCmd(f *factory.Factory) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "networks",
		Short: "Manage networks (subnets)",
		Long:  templates.LongDesc(`Manage NVA networks (subnets): list, get, create, update, delete.`),
	}
	cmd.AddCommand(newListCmd(f, "QueryNetworks", networksQuery,
		"Query network IDs by filter",
		`
            # List all networks
            falcon netscan networks list

            # Filter by name
            falcon netscan networks list --filter "name:*'DC'*"
        `))
	cmd.AddCommand(newGetCmd(f, "GetNetworks", networksEntity,
		"Get networks by ID",
		`
            # Get two networks
            falcon netscan networks get --ids <id1>,<id2>
        `))
	cmd.AddCommand(newNetworkCreateCmd(f))
	cmd.AddCommand(newNetworkUpdateCmd(f))
	cmd.AddCommand(newDeleteCmd(f, "DeleteNetworks", networksEntity,
		"Delete networks by ID",
		`
            # Dry run (prints the plan, calls nothing)
            falcon netscan networks delete --ids <id>

            # Execute
            falcon netscan networks delete --ids <id> --confirm
        `))
	return cmd
}

type networkCreateOptions struct {
	name                 string
	subnet               string
	scannerAssignmentTyp string
	zoneID               string
	scanners             []string
	confirm              bool
	out                  string
}

func newNetworkCreateCmd(f *factory.Factory) *cobra.Command {
	opts := &networkCreateOptions{}
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a network (subnet)",
		Long: templates.LongDesc(`Create an NVA network (subnet).

            This is a mutating action. Without --confirm the command prints the
            request it would send and exits without calling the API.`),
		Example: templates.Examples(`
            # Zone-assigned network (dry run, then execute)
            falcon netscan networks create --name "Core DC" --subnet 10.20.0.0/24 \
                --scanner-assignment-type zone --zone-id <zone_id>
            falcon netscan networks create --name "Core DC" --subnet 10.20.0.0/24 \
                --scanner-assignment-type zone --zone-id <zone_id> --confirm

            # Manually-assigned network
            falcon netscan networks create --name "Lab" --subnet 10.30.0.0/24 \
                --scanner-assignment-type manual --scanner <aid1> --scanner <aid2> --confirm
        `),
		RunE: func(_ *cobra.Command, _ []string) error {
			body := map[string]interface{}{
				"name":                    opts.name,
				"subnet":                  opts.subnet,
				"scanner_assignment_type": opts.scannerAssignmentTyp,
			}
			if opts.zoneID != "" {
				body["zone_id"] = opts.zoneID
			}
			if len(opts.scanners) > 0 {
				body["scanner_aids"] = opts.scanners
			}
			// The entities endpoint takes a list of resources.
			return runWrite(f, "CreateNetworks", "POST", networksEntity, []map[string]interface{}{body}, opts.confirm, opts.out)
		},
	}
	cmd.Flags().StringVar(&opts.name, "name", "", "Network name (required)")
	cmd.Flags().StringVar(&opts.subnet, "subnet", "", "CIDR, e.g. 10.20.0.0/24 (required)")
	cmd.Flags().StringVar(&opts.scannerAssignmentTyp, "scanner-assignment-type", "", "Scanner assignment type: local, zone, or manual (required)")
	cmd.Flags().StringVar(&opts.zoneID, "zone-id", "", "Zone ID (for scanner-assignment-type=zone)")
	cmd.Flags().StringArrayVar(&opts.scanners, "scanner", nil, "Scanner AID (repeatable; for manual assignment)")
	_ = cmd.MarkFlagRequired("name")
	_ = cmd.MarkFlagRequired("subnet")
	_ = cmd.MarkFlagRequired("scanner-assignment-type")
	cmdutil.AddConfirmFlag(cmd, &opts.confirm)
	cmdutil.AddOutputFlag(cmd, &opts.out)
	return cmd
}

type networkUpdateOptions struct {
	id                   string
	name                 string
	ownership            string
	scannerAssignmentTyp string
	zoneID               string
	scanners             []string
	confirm              bool
	out                  string
}

func newNetworkUpdateCmd(f *factory.Factory) *cobra.Command {
	opts := &networkUpdateOptions{}
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update a network",
		Long: templates.LongDesc(`Update an NVA network (subnet).

            This is a mutating action. Without --confirm the command prints the
            request it would send and exits without calling the API.`),
		Example: templates.Examples(`
            # Rename a network (dry run, then execute)
            falcon netscan networks update --id <id> --name "Core DC (renamed)"
            falcon netscan networks update --id <id> --name "Core DC (renamed)" --confirm
        `),
		RunE: func(_ *cobra.Command, _ []string) error {
			body := map[string]interface{}{"id": opts.id}
			if opts.name != "" {
				body["name"] = opts.name
			}
			if opts.ownership != "" {
				body["ownership"] = opts.ownership
			}
			if opts.scannerAssignmentTyp != "" {
				body["scanner_assignment_type"] = opts.scannerAssignmentTyp
			}
			if opts.zoneID != "" {
				body["zone_id"] = opts.zoneID
			}
			if len(opts.scanners) > 0 {
				body["scanner_aids"] = opts.scanners
			}
			return runWrite(f, "UpdateNetworks", "PATCH", networksEntity, []map[string]interface{}{body}, opts.confirm, opts.out)
		},
	}
	cmd.Flags().StringVar(&opts.id, "id", "", "Network ID (required)")
	cmd.Flags().StringVar(&opts.name, "name", "", "New network name")
	cmd.Flags().StringVar(&opts.ownership, "ownership", "", "Ownership: unknown, confirmed, or denied")
	cmd.Flags().StringVar(&opts.scannerAssignmentTyp, "scanner-assignment-type", "", "Scanner assignment type: local, zone, or manual")
	cmd.Flags().StringVar(&opts.zoneID, "zone-id", "", "Zone ID")
	cmd.Flags().StringArrayVar(&opts.scanners, "scanner", nil, "Scanner AID (repeatable)")
	_ = cmd.MarkFlagRequired("id")
	cmdutil.AddConfirmFlag(cmd, &opts.confirm)
	cmdutil.AddOutputFlag(cmd, &opts.out)
	return cmd
}
