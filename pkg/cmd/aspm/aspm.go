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
	"github.com/crowdstrike/falcon-cli/pkg/factory"
	"github.com/spf13/cobra"
	"k8s.io/kubectl/pkg/util/templates"
)

// NewASPMCmd represents the aspm command group (Application Security Posture Management).
func NewASPMCmd(f *factory.Factory) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "aspm",
		Short: "Application Security Posture Management (ASPM)",
		Long: templates.LongDesc(`Query CrowdStrike Falcon ASPM.

            Inspect application-security findings across your services, and read the
            ASPM configuration: integrations, integration types, and service
            violation types.

            This first set of commands is read-only. Findings use the Cloud Security
            application-findings endpoint; the configuration reads use the ASPM API
            gateway.`),
		Example: templates.Examples(`
            # Application-security findings (vulnerabilities for one application)
            falcon aspm findings list --type vulnerabilities --gcrn <gcrn> --filter "severity:'HIGH'"

            # Configured integrations and the available integration types
            falcon aspm integrations list
            falcon aspm integration-types list

            # Service violation taxonomy
            falcon aspm services violation-types
        `),
	}

	cmd.AddCommand(NewCmdFindings(f))
	cmd.AddCommand(NewCmdIntegrations(f))
	cmd.AddCommand(NewCmdIntegrationTypes(f))
	cmd.AddCommand(NewCmdServices(f))
	cmd.AddCommand(NewCmdTags(f))
	return cmd
}
