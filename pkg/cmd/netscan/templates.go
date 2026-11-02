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
	"fmt"

	"github.com/crowdstrike/falcon-cli/pkg/cmdutil"
	"github.com/crowdstrike/falcon-cli/pkg/factory"
	"github.com/spf13/cobra"
	"k8s.io/kubectl/pkg/util/templates"
)

const (
	templatesEntity = "/netscan/entities/templates/v1"
	templatesQuery  = "/netscan/queries/templates/v1"
)

// newTemplatesCmd builds the "templates" subcommand group (scan templates).
func newTemplatesCmd(f *factory.Factory) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "templates",
		Short: "Manage scan templates",
		Long:  templates.LongDesc(`Manage NVA scan templates: list, get, create, update, delete.`),
	}
	cmd.AddCommand(newListCmd(f, "QueryTemplates", templatesQuery,
		"Query scan template IDs",
		`
            # List all templates
            falcon netscan templates list
        `))
	cmd.AddCommand(newGetCmd(f, "GetTemplates", templatesEntity,
		"Get scan templates by ID",
		`
            # Get a template
            falcon netscan templates get --ids <id>
        `))
	cmd.AddCommand(newTemplateWriteCmd(f, true))
	cmd.AddCommand(newTemplateWriteCmd(f, false))
	cmd.AddCommand(newDeleteCmd(f, "DeleteTemplates", templatesEntity,
		"Delete scan templates by ID",
		`
            # Dry run, then execute
            falcon netscan templates delete --ids <id>
            falcon netscan templates delete --ids <id> --confirm
        `))
	return cmd
}

// templateOptions mirrors the Python _template_body() builder.
type templateOptions struct {
	id                       string
	name                     string
	typ                      string
	scanIntensity            string
	portsScanLevel           string
	activeCheckLevel         string
	additionalTCPPorts       []string
	additionalUDPPorts       []string
	excludedTCPPorts         []string
	excludedUDPPorts         []string
	detections               []string
	autoIncludeNewDetections string
	ignoreTCPResets          string
	confirm                  bool
	out                      string
}

// templateBody builds the request body from the options. On create, type is
// included (it is not changeable via update, so PATCH omits it), mirroring the
// Python _template_body(creating=...).
func (o *templateOptions) templateBody(creating bool) (map[string]interface{}, error) {
	body := map[string]interface{}{}
	if o.name != "" {
		body["name"] = o.name
	}
	if creating && o.typ != "" {
		body["type"] = o.typ
	}
	if o.scanIntensity != "" {
		body["scan_intensity"] = o.scanIntensity
	}
	if o.portsScanLevel != "" {
		body["ports_scan_level"] = o.portsScanLevel
	}
	if o.activeCheckLevel != "" {
		body["active_check_level"] = o.activeCheckLevel
	}
	if len(o.additionalTCPPorts) > 0 {
		body["additional_tcp_ports"] = o.additionalTCPPorts
	}
	if len(o.additionalUDPPorts) > 0 {
		body["additional_udp_ports"] = o.additionalUDPPorts
	}
	if len(o.excludedTCPPorts) > 0 {
		body["excluded_tcp_ports"] = o.excludedTCPPorts
	}
	if len(o.excludedUDPPorts) > 0 {
		body["excluded_udp_ports"] = o.excludedUDPPorts
	}
	if len(o.detections) > 0 {
		body["detections"] = o.detections
	}
	autoInclude, err := parseBool("--auto-include-new-detections", o.autoIncludeNewDetections)
	if err != nil {
		return nil, err
	}
	if autoInclude != nil {
		body["auto_include_new_detections"] = *autoInclude
	}
	ignoreResets, err := parseBool("--ignore-tcp-resets", o.ignoreTCPResets)
	if err != nil {
		return nil, err
	}
	if ignoreResets != nil {
		body["ignore_tcp_resets"] = *ignoreResets
	}
	return body, nil
}

// newTemplateWriteCmd builds either the "create" or "update" template subcommand.
func newTemplateWriteCmd(f *factory.Factory, creating bool) *cobra.Command {
	opts := &templateOptions{}
	use := "update"
	short := "Update a scan template"
	method := "PATCH"
	opName := "UpdateTemplates"
	if creating {
		use = "create"
		short = "Create a scan template"
		method = "POST"
		opName = "CreateTemplates"
	}

	cmd := &cobra.Command{
		Use:   use,
		Short: short,
		Long: templates.LongDesc(short + `.

            This is a mutating action. Without --confirm the command prints the
            request it would send and exits without calling the API.`),
		Example: templates.Examples(fmt.Sprintf(`
            # Dry run, then execute
            falcon netscan templates %s --name "DC assessment"
            falcon netscan templates %s --name "DC assessment" --confirm
        `, use, use)),
		RunE: func(_ *cobra.Command, _ []string) error {
			body, err := opts.templateBody(creating)
			if err != nil {
				return err
			}
			if !creating {
				body["id"] = opts.id
			}
			return runWrite(f, opName, method, templatesEntity, []map[string]interface{}{body}, opts.confirm, opts.out)
		},
	}

	if !creating {
		cmd.Flags().StringVar(&opts.id, "id", "", "Template ID (required)")
		_ = cmd.MarkFlagRequired("id")
	}
	cmd.Flags().StringVar(&opts.name, "name", "", "Template name")
	if creating {
		_ = cmd.MarkFlagRequired("name")
		cmd.Flags().StringVar(&opts.typ, "type", "assessment", "Template type: discovery or assessment (set at creation only)")
	}
	cmd.Flags().StringVar(&opts.scanIntensity, "scan-intensity", "", "Scan timing/aggressiveness: basic, standard, cautious, maximum, or custom")
	cmd.Flags().StringVar(&opts.portsScanLevel, "ports-scan-level", "", "Port coverage: default, all_ports, or custom (use custom with --additional-tcp-port/--additional-udp-port)")
	cmd.Flags().StringVar(&opts.activeCheckLevel, "active-check-level", "", "Active checks: active_check_safe_only or active_check_all")
	cmd.Flags().StringArrayVar(&opts.additionalTCPPorts, "additional-tcp-port", nil, "Extra TCP port or range for ports-scan-level=custom (repeatable)")
	cmd.Flags().StringArrayVar(&opts.additionalUDPPorts, "additional-udp-port", nil, "Extra UDP port or range for ports-scan-level=custom (repeatable)")
	cmd.Flags().StringArrayVar(&opts.excludedTCPPorts, "excluded-tcp-port", nil, "TCP port or range to exclude (repeatable)")
	cmd.Flags().StringArrayVar(&opts.excludedUDPPorts, "excluded-udp-port", nil, "UDP port or range to exclude (repeatable)")
	cmd.Flags().StringArrayVar(&opts.detections, "detection", nil, "Detection script name, e.g. cs-libssh-detection.nse (repeatable)")
	cmd.Flags().StringVar(&opts.autoIncludeNewDetections, "auto-include-new-detections", "", "true/false: auto-add new relevant detections over time")
	cmd.Flags().StringVar(&opts.ignoreTCPResets, "ignore-tcp-resets", "", "true/false: ignore TCP resets during the scan")
	cmdutil.AddConfirmFlag(cmd, &opts.confirm)
	cmdutil.AddOutputFlag(cmd, &opts.out)
	return cmd
}
