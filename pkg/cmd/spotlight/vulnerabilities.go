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

package spotlight

import (
	"fmt"
	"strconv"

	"github.com/crowdstrike/falcon-cli/pkg/cmdutil"
	"github.com/crowdstrike/falcon-cli/pkg/factory"
	"github.com/crowdstrike/falcon-cli/pkg/output"
	"github.com/crowdstrike/gofalcon/falcon/client/spotlight_vulnerabilities"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/spf13/cobra"
	"k8s.io/kubectl/pkg/util/templates"
)

var vulnerabilityTableDef = &output.TableDefinition{
	Headers: []string{"CVE_ID", "SEVERITY", "CVSS", "EXPRT_RATING", "STATUS", "HOSTNAME", "AID", "CREATED"},
	RowFunc: func(item any) []string {
		r, ok := item.(*models.DomainBaseAPIVulnerabilityV2)
		if !ok {
			return nil
		}

		cveID := ""
		severity := ""
		cvss := ""
		exprt := ""
		if r.Cve != nil {
			cveID = cmdutil.Deref(r.Cve.ID)
			severity = r.Cve.Severity
			exprt = r.Cve.ExprtRating
			if r.Cve.BaseScore > 0 {
				cvss = strconv.FormatFloat(r.Cve.BaseScore, 'f', -1, 64)
			}
		}

		hostname := ""
		if r.HostInfo != nil {
			hostname = cmdutil.Deref(r.HostInfo.Hostname)
		}

		return []string{
			cveID,
			severity,
			cvss,
			exprt,
			cmdutil.Deref(r.Status),
			hostname,
			cmdutil.Deref(r.Aid),
			cmdutil.Deref(r.CreatedTimestamp),
		}
	},
}

// NewCmdVulnerabilities represents the spotlight vulnerabilities command group.
func NewCmdVulnerabilities(f *factory.Factory) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "vulnerabilities",
		Aliases: []string{"vulns"},
		Short:   "Query Spotlight vulnerabilities",
		Long:    templates.LongDesc(`Query Falcon Spotlight vulnerability entities.`),
		Example: templates.Examples(`
            # List vulnerabilities
            falcon spotlight vulnerabilities list

            # Open, high-severity CVEs only
            falcon spotlight vulns list --filter "status:'open'+cve.severity:'HIGH'"
        `),
	}

	cmd.AddCommand(NewCmdVulnerabilitiesList(f))
	return cmd
}

type vulnerabilitiesListOptions struct {
	Factory *factory.Factory
	filter  string
	sort    string
	limit   int64
	offset  int64
	out     string
	Table   cmdutil.TableFormattingOptions
	Client  cmdutil.ClientFilterOptions
}

// NewCmdVulnerabilitiesList lists Spotlight vulnerabilities matching an optional FQL filter.
func NewCmdVulnerabilitiesList(f *factory.Factory) *cobra.Command {
	opts := &vulnerabilitiesListOptions{Factory: f, limit: 100}

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List Spotlight vulnerabilities",
		Long: templates.LongDesc(`List Spotlight vulnerabilities matching an optional FQL filter.

            Uses the combined query endpoint, which resolves and returns full
            vulnerability entities (CVE, host and remediation detail) in a single
            call. The table shows the CVE, its severity, CVSS base score and
            ExPRT rating, the vulnerability status, the affected host and when it
            was first detected.`),
		Example: templates.Examples(`
            # List all vulnerabilities
            falcon spotlight vulnerabilities list

            # Open, high-severity CVEs only
            falcon spotlight vulns list --filter "status:'open'+cve.severity:'HIGH'"

            # CISA known-exploited vulnerabilities, most recent first
            falcon spotlight vulnerabilities list \
                --filter "cve.is_cisa_kev:true" --sort "created_timestamp|desc"

            # Full detail as JSON
            falcon spotlight vulnerabilities list --output json
        `),
		RunE: func(_ *cobra.Command, _ []string) error {
			// The Spotlight combined endpoint rejects an empty filter with a
			// raw 400 ("filter is required"). Fail fast with an actionable
			// message instead of surfacing the API error.
			if opts.filter == "" {
				return fmt.Errorf("a --filter is required for spotlight vulnerabilities\n" +
					"  the Spotlight API does not allow listing all vulnerabilities unscoped; examples:\n" +
					"    --filter \"status:'open'\"\n" +
					"    --filter \"status:'open'+cve.severity:'CRITICAL'\"\n" +
					"    --filter \"cve.is_cisa_kev:true\"")
			}

			falconClient, err := f.FalconClient()
			if err != nil {
				return err
			}

			// The combined endpoint pages with an opaque `after` token rather
			// than a numeric offset, so to honour --offset without a second
			// call we fetch limit+offset entities and skip the first offset
			// client-side.
			apiLimit := opts.limit
			if opts.offset > 0 {
				apiLimit += opts.offset
			}

			qp := spotlight_vulnerabilities.NewCombinedQueryVulnerabilitiesParams()
			qp.Filter = opts.filter
			if opts.sort != "" {
				qp.Sort = cmdutil.StringPtr(opts.sort)
			}
			qp.Limit = &apiLimit
			qp.Facet = []string{"cve", "host_info", "remediation"}

			resp, err := falconClient.SpotlightVulnerabilities.CombinedQueryVulnerabilities(qp)
			if err != nil {
				return cmdutil.HandleAPIError(err, "CombinedQueryVulnerabilities")
			}

			tableOpts := opts.Table.ToOutputTableOptions()
			printer := output.NewPrinter(output.Format(opts.out), vulnerabilityTableDef, tableOpts)

			if resp.Payload == nil {
				return printer.Print(f.IOStreams.Out, []*models.DomainBaseAPIVulnerabilityV2{})
			}

			resources := resp.Payload.Resources
			if opts.offset > 0 {
				if opts.offset >= int64(len(resources)) {
					resources = []*models.DomainBaseAPIVulnerabilityV2{}
				} else {
					resources = resources[opts.offset:]
				}
			}

			resources = output.FilterAndSort(resources, vulnerabilityTableDef, opts.Client.ToFilterOptions())
			return printer.Print(f.IOStreams.Out, resources)
		},
	}

	cmdutil.AddFilterFlag(cmd, &opts.filter)
	cmdutil.AddSortFlag(cmd, &opts.sort)
	cmdutil.AddPaginationFlags(cmd, &opts.limit, &opts.offset, 100)
	cmdutil.AddOutputFlag(cmd, &opts.out)
	cmdutil.AddTableFormattingFlags(cmd, &opts.Table)
	cmdutil.AddClientFilterFlags(cmd, &opts.Client)
	return cmd
}
