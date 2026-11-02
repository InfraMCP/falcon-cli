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

package rtr

import (
	"github.com/crowdstrike/falcon-cli/pkg/factory"
	"github.com/spf13/cobra"
	"k8s.io/kubectl/pkg/util/templates"
)

// NewRTRCmd represents the real-time-response command group (read-only triage).
func NewRTRCmd(f *factory.Factory) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rtr",
		Short: "Real Time Response (read-only triage)",
		Long: templates.LongDesc(`Inspect Real Time Response (RTR) sessions.

            This group is read-only: it lists existing RTR sessions for triage.
            Executing RTR commands on a host is deliberately not exposed here.`),
		Example: templates.Examples(`
            # List RTR sessions
            falcon rtr sessions list

            # Filter by host
            falcon rtr sessions list --filter "device_id:'<aid>'"
        `),
	}

	cmd.AddCommand(newSessionsCmd(f))
	return cmd
}

func newSessionsCmd(f *factory.Factory) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sessions",
		Short: "Inspect RTR sessions",
	}
	cmd.AddCommand(NewCmdSessionsList(f))
	return cmd
}
