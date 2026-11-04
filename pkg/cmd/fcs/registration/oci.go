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

package registration

import (
	"fmt"

	"github.com/crowdstrike/falcon-cli/pkg/cmdutil"
	"github.com/crowdstrike/falcon-cli/pkg/factory"
	"github.com/crowdstrike/falcon-cli/pkg/output"
	"github.com/crowdstrike/gofalcon/falcon/client/cloud_oci_registration"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/spf13/cobra"
	"k8s.io/kubectl/pkg/util/templates"
)

// NewOCICmd represents the fcs registration oci command group.
func NewOCICmd(f *factory.Factory) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "oci",
		Short: "Manage OCI account registrations",
		Long:  templates.LongDesc(`List, register, and delete OCI (Oracle Cloud) account registrations.`),
	}

	cmd.AddCommand(
		newCmdOCIList(f),
		newCmdOCICreate(f),
		newCmdOCIDelete(f),
	)
	return cmd
}

var ociAccountTableDef = &output.TableDefinition{
	Headers: []string{"REGISTRATION_ID", "HOME_REGION", "STATUS"},
	RowFunc: func(item any) []string {
		r, ok := item.(*models.DomainOCITenancyV1)
		if !ok || r == nil {
			return nil
		}
		regID := ""
		if r.RegistrationID != nil {
			regID = *r.RegistrationID
		}
		homeRegion := ""
		if r.HomeRegion != nil {
			homeRegion = *r.HomeRegion
		}
		status := ""
		if r.OverallStatus != nil {
			status = *r.OverallStatus
		}
		return []string{
			regID,
			homeRegion,
			status,
		}
	},
}

func newCmdOCIList(f *factory.Factory) *cobra.Command {
	var out string

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List registered OCI tenancies",
		Long:  templates.LongDesc(`List all OCI tenancies registered with Falcon Cloud Security.`),
		RunE: func(_ *cobra.Command, _ []string) error {
			client, err := f.FalconClient()
			if err != nil {
				return err
			}

			params := cloud_oci_registration.NewCloudSecurityRegistrationOciGetAccountParams()
			resp, _, _, err := client.CloudOciRegistration.CloudSecurityRegistrationOciGetAccount(params)
			if err != nil {
				return cmdutil.HandleAPIError(err, "list OCI registrations")
			}

			printer := output.NewPrinter(output.Format(out), ociAccountTableDef)
			if resp == nil || resp.Payload == nil {
				return printer.Print(f.IOStreams.Out, nil)
			}
			return printer.Print(f.IOStreams.Out, resp.Payload.Resources)
		},
	}

	cmdutil.AddOutputFlag(cmd, &out)
	return cmd
}

func newCmdOCICreate(f *factory.Factory) *cobra.Command {
	opts := struct {
		tenancyOcid string
		homeRegion  string
		userEmail   string
	}{}

	var confirm bool
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Register an OCI tenancy",
		Long:  templates.LongDesc(`Register a new OCI tenancy with Falcon Cloud Security.`),
		Example: templates.Examples(`
            # Register an OCI tenancy
            falcon fcs registration oci create --tenancy-ocid <ocid> --home-region us-ashburn-1 --user-email admin@example.com
        `),
		RunE: func(_ *cobra.Command, _ []string) error {
			client, dry, err := cmdutil.WriteClient(confirm, f.FalconClient)
			if err != nil {
				return err
			}

			params := cloud_oci_registration.NewCloudSecurityRegistrationOciCreateAccountParams()
			params.Body = &models.DomainOCITenancyCreateRequestExtV1{
				Resources: []*models.DomainOCITenancyCreateExtV1{
					{
						TenancyOcid: &opts.tenancyOcid,
						HomeRegion:  &opts.homeRegion,
						UserEmail:   &opts.userEmail,
						Products:    []*models.DomainCloudOCIProductFeature{},
					},
				},
			}

			resp, _, err := client.CloudOciRegistration.CloudSecurityRegistrationOciCreateAccount(params)
			if err != nil {
				if dry.Intercepted(err) {
					return dry.Print(f.IOStreams.Out)
				}
				return cmdutil.HandleAPIError(err, "create OCI registration")
			}

			if resp != nil && resp.Payload != nil && len(resp.Payload.Resources) > 0 {
				r := resp.Payload.Resources[0]
				tenancyOcid := ""
				if r.TenancyOcid != nil {
					tenancyOcid = *r.TenancyOcid
				}
				fmt.Fprintf(f.IOStreams.Out, "Registered OCI tenancy: %s\n", tenancyOcid)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&opts.tenancyOcid, "tenancy-ocid", "", "OCI tenancy OCID (required)")
	cmd.Flags().StringVar(&opts.homeRegion, "home-region", "", "OCI home region (required)")
	cmd.Flags().StringVar(&opts.userEmail, "user-email", "", "User email for notifications (required)")
	_ = cmd.MarkFlagRequired("tenancy-ocid")
	_ = cmd.MarkFlagRequired("home-region")
	_ = cmd.MarkFlagRequired("user-email")
	cmdutil.AddConfirmFlag(cmd, &confirm)
	return cmd
}

func newCmdOCIDelete(f *factory.Factory) *cobra.Command {
	var ids []string

	var confirm bool
	cmd := &cobra.Command{
		Use:   "delete",
		Short: "Delete OCI registrations",
		Long:  templates.LongDesc(`Delete one or more OCI tenancy registrations from Falcon Cloud Security.`),
		RunE: func(_ *cobra.Command, _ []string) error {
			client, dry, err := cmdutil.WriteClient(confirm, f.FalconClient)
			if err != nil {
				return err
			}

			params := cloud_oci_registration.NewCloudSecurityRegistrationOciDeleteAccountParams()
			params.Ids = ids

			_, _, err = client.CloudOciRegistration.CloudSecurityRegistrationOciDeleteAccount(params)
			if err != nil {
				if dry.Intercepted(err) {
					return dry.Print(f.IOStreams.Out)
				}
				return cmdutil.HandleAPIError(err, "delete OCI registration")
			}

			fmt.Fprintf(f.IOStreams.Out, "Deleted %d OCI registration(s)\n", len(ids))
			return nil
		},
	}

	cmdutil.AddIDsFlag(cmd, &ids, true)
	cmdutil.AddConfirmFlag(cmd, &confirm)
	return cmd
}
