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

package fcs

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/crowdstrike/falcon-cli/pkg/cmd/fcs/iac"
	"github.com/crowdstrike/falcon-cli/pkg/factory"
	"github.com/crowdstrike/falcon-cli/pkg/output"
	"github.com/crowdstrike/gofalcon/falcon/client/a_s_p_m"
	"github.com/crowdstrike/gofalcon/falcon/client/cloud_policies"
	"github.com/crowdstrike/gofalcon/falcon/client/cloud_security_assets"
	"github.com/crowdstrike/gofalcon/falcon/client/code_security_scm_integration"
	"github.com/crowdstrike/gofalcon/falcon/client/code_security_scm_inventory"
	"github.com/crowdstrike/gofalcon/falcon/client/container_images"
	"github.com/crowdstrike/gofalcon/falcon/client/container_vulnerabilities"
	"github.com/crowdstrike/gofalcon/falcon/client/cspg_iacapi"
	"github.com/crowdstrike/gofalcon/falcon/client/kubernetes_protection"
	"github.com/go-openapi/runtime"
	"github.com/spf13/cobra"
	"k8s.io/kubectl/pkg/util/templates"
)

type probeStatus string

const (
	probeOK           probeStatus = "ok"
	probeAccessDenied probeStatus = "access_denied"
	probeNotFound     probeStatus = "not_provisioned"
	probeError        probeStatus = "error"
)

type probeResult struct {
	Command string      `json:"command"`
	Scope   string      `json:"scope"`
	Status  probeStatus `json:"status"`
	Detail  string      `json:"detail,omitempty"`
}

type probeSpec struct {
	Command string
	Scope   string
	fn      func() probeStatus
}

// doctorTableDef renders probe results through the shared output package.
// NOTE: For fancier table rendering (borders, colors), consider adopting a
// library like github.com/jedib0t/go-pretty or github.com/olekukonko/tablewriter.
var doctorTableDef = &output.TableDefinition{
	Headers: []string{"COMMAND", "SCOPE", "STATUS"},
	RowFunc: func(item any) []string {
		r, ok := item.(*probeResult)
		if !ok {
			return nil
		}
		return []string{r.Command, r.Scope, statusIcon(r.Status)}
	},
}

// NewCmdDoctor returns a command that probes each fcs scope group and reports
// which commands will work with the current API credentials.
func NewCmdDoctor(f *factory.Factory) *cobra.Command {
	var outputFmt string

	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Check API client permissions for all fcs commands",
		Long: templates.LongDesc(`
			Probe each Falcon Cloud Security API endpoint with the current credentials
			and report which commands will work, which are missing scopes, and which
			require a feature that is not provisioned in this tenant.

			This is the OAuth2 equivalent of the Falcon console permission checker.
			It makes lightweight read requests (limit=1) to one representative endpoint
			per scope group.`),
		Example: templates.Examples(`
			# Check all fcs command permissions
			falcon fcs doctor

			# Check with a specific profile
			falcon fcs doctor --profile prod

			# Machine-readable output
			falcon fcs doctor --output json
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDoctor(f, outputFmt)
		},
	}

	cmd.Flags().StringVarP(&outputFmt, "output", "o", "table", "Output format: table or json")
	return cmd
}

func runDoctor(f *factory.Factory, outputFmt string) error {
	cfg, err := f.Config()
	if err != nil {
		return err
	}

	falconClient, err := f.FalconClient()
	if err != nil {
		return err
	}

	one := int64(1)

	probes := []probeSpec{
		{
			Command: "fcs assets list / risks list / iom list",
			Scope:   "CSPM Assessment: Read",
			fn: func() probeStatus {
				p := cloud_security_assets.NewCloudSecurityAssetsQueriesParams()
				p.Limit = &one
				_, err := falconClient.CloudSecurityAssets.CloudSecurityAssetsQueries(p)
				return classifyErr(err)
			},
		},
		{
			Command: "fcs iac list",
			Scope:   "IaC Security: Read",
			fn: func() probeStatus {
				p := cspg_iacapi.NewCombinedDetectionsParams()
				p.Limit = &one
				_, err := falconClient.CspgIacapi.CombinedDetections(p, iac.ProbeOption())
				return classifyErr(err)
			},
		},
		{
			Command: "fcs suppression list / groups list",
			Scope:   "CSPM Registration: Read",
			fn: func() probeStatus {
				p := cloud_policies.NewQuerySuppressionRulesParams()
				p.Limit = &one
				_, err := falconClient.CloudPolicies.QuerySuppressionRules(p)
				return classifyErr(err)
			},
		},
		{
			Command: "fcs compliance frameworks / rules",
			Scope:   "CSPM Registration: Read + Compliance posture feature",
			fn: func() probeStatus {
				p := cloud_policies.NewQueryComplianceFrameworksParams()
				p.Limit = &one
				_, err := falconClient.CloudPolicies.QueryComplianceFrameworks(p)
				return classifyErr(err)
			},
		},
		{
			Command: "fcs kubernetes clusters / containers",
			Scope:   "Falcon Container Image: Read",
			fn: func() probeStatus {
				p := kubernetes_protection.NewClusterCombinedParams()
				p.Limit = &one
				_, err := falconClient.KubernetesProtection.ClusterCombined(p)
				return classifyErr(err)
			},
		},
		{
			Command: "fcs kubernetes images",
			Scope:   "Falcon Container Image: Read",
			fn: func() probeStatus {
				p := container_images.NewCombinedImageDetailParams()
				p.Limit = &one
				_, err := falconClient.ContainerImages.CombinedImageDetail(p)
				return classifyErr(err)
			},
		},
		{
			Command: "fcs vulnerabilities list",
			Scope:   "Falcon Container Image: Read",
			fn: func() probeStatus {
				p := container_vulnerabilities.NewReadCombinedVulnerabilitiesParams()
				p.Limit = &one
				_, err := falconClient.ContainerVulnerabilities.ReadCombinedVulnerabilities(p)
				return classifyErr(err)
			},
		},
		{
			Command: "aspm findings list",
			Scope:   "Cloud Security API Assets: Read",
			fn: func() probeStatus {
				// We deliberately omit gcrn here, so a 400 (bad request) means
				// the endpoint is reachable and authorized — treat it as OK.
				// A 403 still means the scope is missing.
				p := cloud_security_assets.NewCloudSecurityAssetsCombinedApplicationFindingsParams()
				p.Type = "vulnerabilities"
				p.Limit = &one
				_, err := falconClient.CloudSecurityAssets.CloudSecurityAssetsCombinedApplicationFindings(p)
				if st := classifyErr(err); st != probeError {
					return st
				}
				// classifyErr only understands runtime.APIError; this endpoint
				// returns a typed response error exposing Code(). A 400 here
				// means reachable + authorized (we sent no gcrn), so treat it
				// as OK; anything else stays an error.
				if coder, ok := err.(interface{ Code() int }); ok && coder.Code() == 400 {
					return probeOK
				}
				return probeError
			},
		},
		{
			Command: "aspm integrations / services",
			Scope:   "ASPM Read-Only: Read",
			fn: func() probeStatus {
				p := a_s_p_m.NewGetIntegrationsParams()
				_, err := falconClient.Aspm.GetIntegrations(p)
				return classifyErr(err)
			},
		},
		{
			Command: "aspm integration-types list",
			Scope:   "ASPM Admin: Read",
			fn: func() probeStatus {
				p := a_s_p_m.NewGetIntegrationTypesParams()
				_, err := falconClient.Aspm.GetIntegrationTypes(p)
				return classifyErr(err)
			},
		},
		{
			Command: "code-security connections / exclusions / branch-configs",
			Scope:   "Code Security Scm Integration: Read",
			fn: func() probeStatus {
				p := code_security_scm_integration.NewListSCMConnectionsParams()
				_, err := falconClient.CodeSecurityScmIntegration.ListSCMConnections(p)
				return classifyErr(err)
			},
		},
		{
			Command: "code-security repositories / pull-jobs",
			Scope:   "Code Security Scm Inventory: Read",
			fn: func() probeStatus {
				p := code_security_scm_inventory.NewListSCMRepositoriesParams()
				p.Limit = &one
				_, err := falconClient.CodeSecurityScmInventory.ListSCMRepositories(p)
				return classifyErr(err)
			},
		},
	}

	// Run all probes
	results := make([]*probeResult, 0, len(probes))
	for _, p := range probes {
		status := p.fn()
		detail := ""
		switch status {
		case probeAccessDenied:
			detail = "HTTP 403 — add scope or check CWPP product provisioning"
		case probeNotFound:
			detail = "HTTP 404 — feature not provisioned in this tenant"
		case probeError:
			detail = "unexpected error"
		}
		results = append(results, &probeResult{
			Command: p.Command,
			Scope:   p.Scope,
			Status:  status,
			Detail:  detail,
		})
	}

	if outputFmt == "json" {
		return printDoctorJSON(f, results)
	}

	// Print client ID prefix for context
	if cfg.ClientID != "" {
		fmt.Fprintf(f.IOStreams.Out, "\nChecking permissions for client: %s...\n\n", cfg.ClientID[:min(8, len(cfg.ClientID))])
	}

	printer := output.NewPrinter(output.FormatTable, doctorTableDef)
	if err := printer.Print(f.IOStreams.Out, results); err != nil {
		return err
	}

	// Summary footer
	missingScopes := map[string][]string{}
	ok, denied, notFound, errCount := 0, 0, 0, 0
	for _, r := range results {
		switch r.Status {
		case probeOK:
			ok++
		case probeAccessDenied:
			denied++
			basescope := strings.Split(r.Scope, " +")[0]
			missingScopes[basescope] = append(missingScopes[basescope], r.Command)
		case probeNotFound:
			notFound++
		default:
			errCount++
		}
	}

	out := f.IOStreams.Out
	fmt.Fprintln(out)
	if len(missingScopes) > 0 {
		fmt.Fprintln(out, "Missing scopes — add at https://falcon.crowdstrike.com/api-clients-and-keys:")
		for scope, cmds := range missingScopes {
			fmt.Fprintf(out, "  • %s\n", scope)
			fmt.Fprintf(out, "    Commands: %s\n", strings.Join(cmds, ", "))
		}
		fmt.Fprintln(out)
		fmt.Fprintln(out, "  Note: If the scope is already enabled, the Falcon Cloud Workload Protection")
		fmt.Fprintln(out, "  (CWPP) product may not be provisioned in this tenant.")
		fmt.Fprintln(out, "  Contact your Falcon admin to verify product entitlements.")
		fmt.Fprintln(out)
	}
	fmt.Fprintf(out, "Results: ✅ %d available  ❌ %d access denied  ⚠️  %d not provisioned\n\n", ok, denied, notFound+errCount)
	return nil
}

func classifyErr(err error) probeStatus {
	if err == nil {
		return probeOK
	}
	var apiErr *runtime.APIError
	if errors.As(err, &apiErr) {
		switch apiErr.Code {
		case 403:
			return probeAccessDenied
		case 404:
			return probeNotFound
		}
	}
	return probeError
}

func printDoctorJSON(f *factory.Factory, results []*probeResult) error {
	enc := json.NewEncoder(f.IOStreams.Out)
	enc.SetIndent("", "  ")
	return enc.Encode(results)
}

func statusIcon(s probeStatus) string {
	switch s {
	case probeOK:
		return "✅"
	case probeAccessDenied:
		return "❌"
	case probeNotFound:
		return "⚠️ "
	default:
		return "⚠️ "
	}
}
