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
	"github.com/crowdstrike/falcon-cli/pkg/cmd/fcs/assets"
	"github.com/crowdstrike/falcon-cli/pkg/cmd/fcs/cloudgroups"
	"github.com/crowdstrike/falcon-cli/pkg/cmd/fcs/compliance"
	"github.com/crowdstrike/falcon-cli/pkg/cmd/fcs/groups"
	"github.com/crowdstrike/falcon-cli/pkg/cmd/fcs/iac"
	"github.com/crowdstrike/falcon-cli/pkg/cmd/fcs/imageassessment"
	"github.com/crowdstrike/falcon-cli/pkg/cmd/fcs/iom"
	"github.com/crowdstrike/falcon-cli/pkg/cmd/fcs/kubernetes"
	"github.com/crowdstrike/falcon-cli/pkg/cmd/fcs/policies"
	"github.com/crowdstrike/falcon-cli/pkg/cmd/fcs/registration"
	"github.com/crowdstrike/falcon-cli/pkg/cmd/fcs/risks"
	"github.com/crowdstrike/falcon-cli/pkg/cmd/fcs/suppression"
	"github.com/crowdstrike/falcon-cli/pkg/cmd/fcs/vulnerabilities"
	"github.com/crowdstrike/falcon-cli/pkg/factory"
	"github.com/spf13/cobra"
	"k8s.io/kubectl/pkg/util/templates"
)

// NewFCSCmd represents the fcs command group.
func NewFCSCmd(f *factory.Factory) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "fcs",
		Short: "Manage Falcon Cloud Security resources",
		Long:  templates.LongDesc(`Manage Falcon Cloud Security (FCS) resources including risks, assets, misconfigurations, compliance, Kubernetes, and more.`),
	}

	cmd.AddCommand(
		risks.NewRisksCmd(f),
		assets.NewAssetsCmd(f),
		iom.NewIOMCmd(f),
		compliance.NewComplianceCmd(f),
		suppression.NewSuppressionCmd(f),
		groups.NewGroupsCmd(f),
		cloudgroups.NewCloudGroupsCmd(f),
		kubernetes.NewKubernetesCmd(f),
		vulnerabilities.NewVulnerabilitiesCmd(f),
		iac.NewIACCmd(f),
		imageassessment.NewImageAssessmentCmd(f),
		policies.NewPoliciesCmd(f),
		registration.NewRegistrationCmd(f),
		NewCmdDoctor(f),
	)
	return cmd
}
