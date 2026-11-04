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
	"github.com/crowdstrike/gofalcon/falcon/client/cloud_aws_registration"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/spf13/cobra"
	"k8s.io/kubectl/pkg/util/templates"
)

// NewCmdAWSCreate represents the fcs registration aws create command.
func NewCmdAWSCreate(f *factory.Factory) *cobra.Command {
	opts := struct {
		accountID   string
		accountType string
	}{}

	var confirm bool
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Register an AWS account",
		Long:  templates.LongDesc(`Register a new AWS account with Falcon Cloud Security.`),
		Example: templates.Examples(`
            # Register an AWS account
            falcon fcs registration aws create --account-id 123456789012

            # Register an organization management account
            falcon fcs registration aws create --account-id 123456789012 --account-type organization
        `),
		RunE: func(_ *cobra.Command, _ []string) error {
			client, dry, err := cmdutil.WriteClient(confirm, f.FalconClient)
			if err != nil {
				return err
			}

			params := cloud_aws_registration.NewCloudRegistrationAwsCreateAccountParams()
			params.Body = &models.RestAWSAccountCreateRequestExtv1{
				Resources: []*models.RestCloudAWSAccountCreateExtV1{
					{
						AccountID:   opts.accountID,
						AccountType: opts.accountType,
					},
				},
			}

			resp, _, err := client.CloudAwsRegistration.CloudRegistrationAwsCreateAccount(params)
			if err != nil {
				if dry.Intercepted(err) {
					return dry.Print(f.IOStreams.Out)
				}
				return cmdutil.HandleAPIError(err, "create AWS account registration")
			}

			if resp != nil && resp.Payload != nil && len(resp.Payload.Resources) > 0 {
				acct := resp.Payload.Resources[0]
				fmt.Fprintf(f.IOStreams.Out, "Registered AWS account: %s (%s)\n", acct.AccountID, acct.AccountName)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&opts.accountID, "account-id", "", "AWS account ID (required)")
	cmd.Flags().StringVar(&opts.accountType, "account-type", "single", "Account type (single, organization)")
	_ = cmd.MarkFlagRequired("account-id")
	cmdutil.AddConfirmFlag(cmd, &confirm)
	return cmd
}
