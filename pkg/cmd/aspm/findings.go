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

package aspm

import (
	"fmt"
	"strconv"

	"github.com/crowdstrike/falcon-cli/pkg/cmdutil"
	"github.com/crowdstrike/falcon-cli/pkg/factory"
	"github.com/crowdstrike/falcon-cli/pkg/output"
	"github.com/crowdstrike/gofalcon/falcon/client/cloud_security_assets"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/spf13/cobra"
	"k8s.io/kubectl/pkg/util/templates"
)

var findingsTableDef = &output.TableDefinition{
	Headers: []string{"CRN", "FINDING_TYPE", "FINDINGS"},
	RowFunc: func(item any) []string {
		r, ok := item.(*models.AssetsResourceApplicationFindingsItem)
		if !ok {
			return nil
		}
		return []string{
			cmdutil.Deref(r.Crn),
			cmdutil.Deref(r.FindingType),
			strconv.Itoa(len(r.Findings)),
		}
	},
}

// NewCmdFindings represents the aspm findings command group.
func NewCmdFindings(f *factory.Factory) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "findings",
		Short: "Application-security findings",
		Long: templates.LongDesc(`Query ASPM application-security findings.

            Findings are grouped by resource (CRN) and finding type. The table
            shows each resource, its finding type and how many findings it has;
            use --output json for the full finding detail, which varies by type.`),
		Example: templates.Examples(`
            # Vulnerability findings, high severity
            falcon aspm findings list --type vulnerabilities --filter "severity:'HIGH'"

            # Package findings for one application (by gcrn), full detail
            falcon aspm findings list --type packages --gcrn <gcrn> --output json
        `),
	}

	cmd.AddCommand(NewCmdFindingsList(f))
	return cmd
}

type findingsListOptions struct {
	Factory     *factory.Factory
	findingType string
	crn         string
	gcrn        string
	filter      string
	sort        string
	limit       int64
	offset      int64
	out         string
	Table       cmdutil.TableFormattingOptions
	Client      cmdutil.ClientFilterOptions
}

// NewCmdFindingsList lists ASPM application findings of a given type.
func NewCmdFindingsList(f *factory.Factory) *cobra.Command {
	opts := &findingsListOptions{Factory: f, limit: 100}

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List application-security findings",
		Long: templates.LongDesc(`List ASPM application-security findings of a given type.

            --type is required (e.g. vulnerabilities, packages, datastore_access).
            Select the application with --gcrn (or a specific resource with --crn).
            --filter is an FQL expression over the finding content (not an asset
            filter); --sort takes a "field|direction" expression supported by the
            chosen finding type.`),
		Example: templates.Examples(`
            # High-severity vulnerability findings
            falcon aspm findings list --type vulnerabilities --filter "severity:'HIGH'"

            # Packages for one application, newest key first
            falcon aspm findings list --type packages --gcrn <gcrn> --sort "key|desc"

            # Full detail as JSON
            falcon aspm findings list --type vulnerabilities --output json
        `),
		RunE: func(_ *cobra.Command, _ []string) error {
			// The application-findings endpoint selects an application via gcrn
			// (or a specific resource via crn); without one it returns a bare
			// 400. Fail fast with an actionable message instead.
			if opts.gcrn == "" && opts.crn == "" {
				return fmt.Errorf("a --gcrn (or --crn) is required for aspm findings\n" +
					"  findings are scoped to one application; the endpoint rejects an unscoped list.\n" +
					"  pass the application's gCRN:\n" +
					"    falcon aspm findings list --type vulnerabilities --gcrn <gcrn>")
			}

			falconClient, err := f.FalconClient()
			if err != nil {
				return err
			}

			p := cloud_security_assets.NewCloudSecurityAssetsCombinedApplicationFindingsParams()
			p.Type = opts.findingType
			if opts.crn != "" {
				p.Crn = cmdutil.StringPtr(opts.crn)
			}
			if opts.gcrn != "" {
				p.Gcrn = cmdutil.StringPtr(opts.gcrn)
			}
			if opts.filter != "" {
				p.Filter = cmdutil.StringPtr(opts.filter)
			}
			if opts.sort != "" {
				p.Sort = cmdutil.StringPtr(opts.sort)
			}
			p.Limit = cmdutil.Int64Ptr(opts.limit)
			if opts.offset > 0 {
				p.Offset = cmdutil.Int64Ptr(opts.offset)
			}

			resp, err := falconClient.CloudSecurityAssets.CloudSecurityAssetsCombinedApplicationFindings(p)
			if err != nil {
				return cmdutil.HandleAPIError(err, "CloudSecurityAssetsCombinedApplicationFindings")
			}

			tableOpts := opts.Table.ToOutputTableOptions()
			printer := output.NewPrinter(output.Format(opts.out), findingsTableDef, tableOpts)

			if resp.Payload == nil {
				return printer.Print(f.IOStreams.Out, []*models.AssetsResourceApplicationFindingsItem{})
			}

			resources := output.FilterAndSort(resp.Payload.Resources, findingsTableDef, opts.Client.ToFilterOptions())
			return printer.Print(f.IOStreams.Out, resources)
		},
	}

	cmd.Flags().StringVar(&opts.findingType, "type", "", "Finding type (required, e.g. vulnerabilities, packages, datastore_access)")
	_ = cmd.MarkFlagRequired("type")
	cmd.Flags().StringVar(&opts.crn, "crn", "", "Select a specific resource by CRN")
	cmd.Flags().StringVar(&opts.gcrn, "gcrn", "", "Select the application by gCRN")
	cmdutil.AddFilterFlag(cmd, &opts.filter)
	cmdutil.AddSortFlag(cmd, &opts.sort)
	cmdutil.AddPaginationFlags(cmd, &opts.limit, &opts.offset, 100)
	cmdutil.AddOutputFlag(cmd, &opts.out)
	cmdutil.AddTableFormattingFlags(cmd, &opts.Table)
	cmdutil.AddClientFilterFlags(cmd, &opts.Client)
	return cmd
}
