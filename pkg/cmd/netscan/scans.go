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
	"encoding/json"
	"fmt"

	"github.com/crowdstrike/falcon-cli/pkg/cmdutil"
	"github.com/crowdstrike/falcon-cli/pkg/factory"
	"github.com/spf13/cobra"
	"k8s.io/kubectl/pkg/util/templates"
)

const (
	scansEntity = "/netscan/entities/scans/v1"
	scansQuery  = "/netscan/queries/scans/v1"
)

// newScansCmd builds the "scans" subcommand group (scan configurations).
func newScansCmd(f *factory.Factory) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scans",
		Short: "Manage scan configurations",
		Long:  templates.LongDesc(`Manage NVA scan configurations: list, get, create, update, delete.`),
	}
	cmd.AddCommand(newListCmd(f, "QueryScans", scansQuery,
		"Query scan IDs by filter",
		`
            # List all scan configurations
            falcon netscan scans list
        `))
	cmd.AddCommand(newGetCmd(f, "GetScans", scansEntity,
		"Get scans by ID",
		`
            # Get a scan configuration
            falcon netscan scans get --ids <id>
        `))
	cmd.AddCommand(newScanWriteCmd(f, true))
	cmd.AddCommand(newScanWriteCmd(f, false))
	cmd.AddCommand(newDeleteCmd(f, "DeleteScans", scansEntity,
		"Delete scans by ID",
		`
            # Dry run, then execute
            falcon netscan scans delete --ids <id>
            falcon netscan scans delete --ids <id> --confirm
        `))
	return cmd
}

// scanOptions holds the flags for scan create/update. It mirrors the fields of
// the Python falcon-netscan _scan_body() builder.
type scanOptions struct {
	id                     string
	name                   string
	description            string
	templateID             string
	targetType             string
	targetIP               []string
	targetZoneID           string
	targetExternalIP       []string
	targetAsset            string
	targetAssetFilter      string
	scheduling             string
	credentials            string
	credentialed           string
	fragileDeviceDetection string
	confirm                bool
	out                    string
}

// jsonArg parses a JSON-valued flag into an arbitrary object.
func jsonArg(flag, value string) (interface{}, error) {
	var v interface{}
	if err := json.Unmarshal([]byte(value), &v); err != nil {
		return nil, fmt.Errorf("%s must be valid JSON: %w", flag, err)
	}
	return v, nil
}

// parseBool parses a true/false flag value (empty string means "unset").
func parseBool(flag, value string) (*bool, error) {
	switch value {
	case "":
		return nil, nil
	case "true", "1", "yes":
		b := true
		return &b, nil
	case "false", "0", "no":
		b := false
		return &b, nil
	default:
		return nil, fmt.Errorf("%s expected true or false, got %q", flag, value)
	}
}

// scanBody builds the request body from the options, mirroring the Python
// _scan_body(). creating=true seeds the fragile_device_detection default.
func (o *scanOptions) scanBody(creating bool) (map[string]interface{}, error) {
	body := map[string]interface{}{}
	if o.name != "" {
		body["name"] = o.name
	}
	if o.description != "" {
		body["description"] = o.description
	}
	if o.templateID != "" {
		body["template_id"] = o.templateID
	}
	if o.targetType != "" {
		body["target_type"] = o.targetType
	}
	if len(o.targetIP) > 0 {
		// target_ip is an object: {zone_id?, ip_specs:[...]}.
		spec := map[string]interface{}{"ip_specs": o.targetIP}
		if o.targetZoneID != "" {
			spec["zone_id"] = o.targetZoneID
		}
		body["target_ip"] = spec
	}
	if len(o.targetExternalIP) > 0 {
		body["target_external_ip"] = map[string]interface{}{"ip_specs": o.targetExternalIP}
	}
	if o.targetAsset != "" {
		v, err := jsonArg("--target-asset", o.targetAsset)
		if err != nil {
			return nil, err
		}
		body["target_asset"] = v
	}
	if o.targetAssetFilter != "" {
		v, err := jsonArg("--target-asset-filter", o.targetAssetFilter)
		if err != nil {
			return nil, err
		}
		body["target_asset_filter"] = v
	}
	if o.scheduling != "" {
		v, err := jsonArg("--scheduling", o.scheduling)
		if err != nil {
			return nil, err
		}
		body["scheduling"] = v
	}
	if o.credentials != "" {
		v, err := jsonArg("--credentials", o.credentials)
		if err != nil {
			return nil, err
		}
		body["credentials"] = v
	}
	credentialed, err := parseBool("--credentialed", o.credentialed)
	if err != nil {
		return nil, err
	}
	if credentialed != nil {
		body["credentialed"] = *credentialed
	}
	fragile, err := parseBool("--fragile-device-detection", o.fragileDeviceDetection)
	if err != nil {
		return nil, err
	}
	if fragile != nil {
		body["fragile_device_detection"] = *fragile
	} else if creating {
		// The scans create endpoint requires fragile_device_detection; default
		// it to false (matches targeted scans of a known host list) so callers
		// don't hit a 400.
		body["fragile_device_detection"] = false
	}
	return body, nil
}

// newScanWriteCmd builds either the "create" or "update" scan subcommand.
func newScanWriteCmd(f *factory.Factory, creating bool) *cobra.Command {
	opts := &scanOptions{}
	use := "update"
	short := "Update a scan configuration"
	method := "PATCH"
	opName := "UpdateScans"
	if creating {
		use = "create"
		short = "Create a scan configuration"
		method = "POST"
		opName = "CreateScans"
	}

	cmd := &cobra.Command{
		Use:   use,
		Short: short,
		Long: templates.LongDesc(short + `.

            This is a mutating action. Without --confirm the command prints the
            request it would send and exits without calling the API.`),
		Example: templates.Examples(fmt.Sprintf(`
            # Dry run, then execute
            falcon netscan scans %s --name "Weekly DC scan" --target-type ip \
                --target-ip 10.20.0.0/24 --template-id <template_id>
            falcon netscan scans %s --name "Weekly DC scan" --target-type ip \
                --target-ip 10.20.0.0/24 --template-id <template_id> --confirm
        `, use, use)),
		RunE: func(_ *cobra.Command, _ []string) error {
			body, err := opts.scanBody(creating)
			if err != nil {
				return err
			}
			if !creating {
				body["id"] = opts.id
			}
			return runWrite(f, opName, method, scansEntity, []map[string]interface{}{body}, opts.confirm, opts.out)
		},
	}

	if !creating {
		cmd.Flags().StringVar(&opts.id, "id", "", "Scan ID (required)")
		_ = cmd.MarkFlagRequired("id")
	}
	cmd.Flags().StringVar(&opts.name, "name", "", "Scan name")
	if creating {
		_ = cmd.MarkFlagRequired("name")
	}
	cmd.Flags().StringVar(&opts.description, "description", "", "Scan description")
	cmd.Flags().StringVar(&opts.templateID, "template-id", "", "Scan template ID")
	cmd.Flags().StringVar(&opts.targetType, "target-type", "", "Target type: ip, asset, asset_filter, asset_vuln, or external_ip")
	cmd.Flags().StringArrayVar(&opts.targetIP, "target-ip", nil, "Target IP or CIDR for target-type=ip (repeatable; each goes into ip_specs)")
	cmd.Flags().StringVar(&opts.targetZoneID, "target-zone-id", "", "Site zone ID for the target_ip object (target-type=ip)")
	cmd.Flags().StringArrayVar(&opts.targetExternalIP, "target-external-ip", nil, "Target external IP/CIDR for target-type=external_ip (repeatable)")
	cmd.Flags().StringVar(&opts.targetAsset, "target-asset", "", "JSON object for target-type=asset")
	cmd.Flags().StringVar(&opts.targetAssetFilter, "target-asset-filter", "", "JSON object for target-type=asset_filter")
	cmd.Flags().StringVar(&opts.scheduling, "scheduling", "", "JSON scheduling object")
	cmd.Flags().StringVar(&opts.credentials, "credentials", "", "JSON credentials object")
	cmd.Flags().StringVar(&opts.credentialed, "credentialed", "", "true/false: whether the scan is credentialed")
	cmd.Flags().StringVar(&opts.fragileDeviceDetection, "fragile-device-detection", "", "true/false: include fragile-device detection")
	cmdutil.AddConfirmFlag(cmd, &opts.confirm)
	cmdutil.AddOutputFlag(cmd, &opts.out)
	return cmd
}
