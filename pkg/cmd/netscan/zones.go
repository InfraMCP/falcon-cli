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
	zonesEntity   = "/netscan/entities/zones/v1"
	zonesCombined = "/netscan/combined/zones/v1"
)

// newZonesCmd builds the "zones" subcommand group (scan zones).
func newZonesCmd(f *factory.Factory) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "zones",
		Short: "Manage scan zones",
		Long:  templates.LongDesc(`Manage NVA scan zones: list, get, create, update, delete.`),
	}
	// Zones list uses the combined endpoint (returns full resources in one call),
	// matching the Python falcon-netscan zones_list().
	cmd.AddCommand(newListCmd(f, "GetZonesCombined", zonesCombined,
		"Get zones by filter (combined)",
		`
            # List all zones
            falcon netscan zones list

            # Filter by name
            falcon netscan zones list --filter "name:*'Syd'*"
        `))
	cmd.AddCommand(newGetCmd(f, "GetZones", zonesEntity,
		"Get zones by ID",
		`
            # Get a zone
            falcon netscan zones get --ids <id>
        `))
	cmd.AddCommand(newZoneCreateCmd(f))
	cmd.AddCommand(newZoneUpdateCmd(f))
	cmd.AddCommand(newDeleteCmd(f, "DeleteZones", zonesEntity,
		"Delete zones by ID",
		`
            # Dry run, then execute
            falcon netscan zones delete --ids <id>
            falcon netscan zones delete --ids <id> --confirm
        `))
	return cmd
}

type zoneCreateOptions struct {
	name     string
	scanners []string
	confirm  bool
	out      string
}

func newZoneCreateCmd(f *factory.Factory) *cobra.Command {
	opts := &zoneCreateOptions{}
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a zone",
		Long: templates.LongDesc(`Create an NVA scan zone.

            This is a mutating action. Without --confirm the command prints the
            request it would send and exits without calling the API.`),
		Example: templates.Examples(`
            # Create a zone with two scanners (dry run, then execute)
            falcon netscan zones create --name "Sydney" --scanner <aid1> --scanner <aid2>
            falcon netscan zones create --name "Sydney" --scanner <aid1> --scanner <aid2> --confirm
        `),
		RunE: func(_ *cobra.Command, _ []string) error {
			body := map[string]interface{}{"name": opts.name}
			if len(opts.scanners) > 0 {
				body["scanners"] = opts.scanners
			}
			return runWrite(f, "CreateZones", "POST", zonesEntity, []map[string]interface{}{body}, opts.confirm, opts.out)
		},
	}
	cmd.Flags().StringVar(&opts.name, "name", "", "Zone name (required)")
	cmd.Flags().StringArrayVar(&opts.scanners, "scanner", nil, "Scanner AID (repeatable)")
	_ = cmd.MarkFlagRequired("name")
	cmdutil.AddConfirmFlag(cmd, &opts.confirm)
	cmdutil.AddOutputFlag(cmd, &opts.out)
	return cmd
}

type zoneUpdateOptions struct {
	id             string
	name           string
	addScanners    []string
	removeScanners []string
	confirm        bool
	out            string
}

func newZoneUpdateCmd(f *factory.Factory) *cobra.Command {
	opts := &zoneUpdateOptions{}
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update a zone",
		Long: templates.LongDesc(`Update an NVA scan zone.

            This is a mutating action. Without --confirm the command prints the
            request it would send and exits without calling the API.`),
		Example: templates.Examples(`
            # Add a scanner to a zone (dry run, then execute)
            falcon netscan zones update --id <id> --add-scanner <aid>
            falcon netscan zones update --id <id> --add-scanner <aid> --confirm
        `),
		RunE: func(_ *cobra.Command, _ []string) error {
			body := map[string]interface{}{"id": opts.id}
			if opts.name != "" {
				body["name"] = opts.name
			}
			if len(opts.addScanners) > 0 {
				body["scanners_to_add"] = opts.addScanners
			}
			if len(opts.removeScanners) > 0 {
				body["scanners_to_remove"] = opts.removeScanners
			}
			return runWrite(f, "UpdateZones", "PATCH", zonesEntity, []map[string]interface{}{body}, opts.confirm, opts.out)
		},
	}
	cmd.Flags().StringVar(&opts.id, "id", "", "Zone ID (required)")
	cmd.Flags().StringVar(&opts.name, "name", "", "New zone name")
	cmd.Flags().StringArrayVar(&opts.addScanners, "add-scanner", nil, "Scanner AID to add (repeatable)")
	cmd.Flags().StringArrayVar(&opts.removeScanners, "remove-scanner", nil, "Scanner AID to remove (repeatable)")
	_ = cmd.MarkFlagRequired("id")
	cmdutil.AddConfirmFlag(cmd, &opts.confirm)
	cmdutil.AddOutputFlag(cmd, &opts.out)
	return cmd
}
