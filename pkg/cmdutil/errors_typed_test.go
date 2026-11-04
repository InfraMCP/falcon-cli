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

package cmdutil

import (
	"strings"
	"testing"

	scminv "github.com/crowdstrike/gofalcon/falcon/client/code_security_scm_inventory"
	"github.com/crowdstrike/gofalcon/falcon/models"
)

func TestHandleAPIError_TypedNotFoundUsesAPIMessage(t *testing.T) {
	msg := "pull job not found"
	e := scminv.NewGetPullJobNotFound()
	e.Payload = &models.APIResponse{Errors: []*models.MsaAPIError{{Code: Int32Ptr(404), Message: &msg}}}
	got := HandleAPIError(e, "GetPullJob").Error()
	if !strings.Contains(got, "HTTP 404") || !strings.Contains(got, msg) || strings.Contains(got, "trace_id") {
		t.Fatalf("got %q", got)
	}
}

func TestStatusCode_NonHTTPError(t *testing.T) {
	if _, ok := statusCode(errString("boom")); ok {
		t.Fatal("plain error must not report a status")
	}
}

type errString string

func (e errString) Error() string { return string(e) }
