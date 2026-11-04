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

// NewCmdAWSUpdate represents the fcs registration aws update command.
func NewCmdAWSUpdate(f *factory.Factory) *cobra.Command {
	opts := struct {
		accountID string
	}{}

	var confirm bool
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update an AWS account registration",
		Long:  templates.LongDesc(`Update an existing AWS account registration with Falcon Cloud Security.`),
		Example: templates.Examples(`
            # Update an AWS account
            falcon fcs registration aws update --account-id 123456789012
        `),
		RunE: func(_ *cobra.Command, _ []string) error {
			client, dry, err := cmdutil.WriteClient(confirm, f.FalconClient)
			if err != nil {
				return err
			}

			params := cloud_aws_registration.NewCloudRegistrationAwsUpdateAccountParams()
			params.Body = &models.RestAWSAccountPatchRequestExtV1{
				Resources: []*models.RestAWSAccountPatchExtV1{
					{
						AccountID: &opts.accountID,
					},
				},
			}

			resp, _, err := client.CloudAwsRegistration.CloudRegistrationAwsUpdateAccount(params)
			if err != nil {
				if dry.Intercepted(err) {
					return dry.Print(f.IOStreams.Out)
				}
				return cmdutil.HandleAPIError(err, "update AWS account registration")
			}

			if resp != nil && resp.Payload != nil && len(resp.Payload.Resources) > 0 {
				acct := resp.Payload.Resources[0]
				fmt.Fprintf(f.IOStreams.Out, "Updated AWS account: %s\n", acct.AccountID)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&opts.accountID, "account-id", "", "AWS account ID (required)")
	_ = cmd.MarkFlagRequired("account-id")
	cmdutil.AddConfirmFlag(cmd, &confirm)
	return cmd
}
