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
	"bytes"
	"errors"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/cloud_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

type fakeTransport struct{ ops []string }

func (f *fakeTransport) Submit(op *runtime.ClientOperation) (any, error) {
	f.ops = append(f.ops, op.Method+" "+op.PathPattern)
	return nil, errors.New("fake read")
}

func TestWriteClient_RecordsDeleteWithoutSending(t *testing.T) {
	called := false
	c, dry, err := WriteClient(false, func() (*client.CrowdStrikeAPISpecification, error) {
		called = true
		return nil, errors.New("must not be called for a write-only dry run")
	})
	if err != nil {
		t.Fatal(err)
	}
	p := cloud_policies.NewDeleteSuppressionRulesParams()
	p.Ids = []string{"a", "b"}
	_, err = c.CloudPolicies.DeleteSuppressionRules(p)
	if !dry.Intercepted(err) {
		t.Fatalf("want ErrDryRun, got %v", err)
	}
	if called {
		t.Fatal("dry run of a write must not create a real client")
	}
	plans := dry.Plans()
	if len(plans) != 1 || plans[0].Method != "DELETE" || len(plans[0].IDs) != 2 {
		t.Fatalf("unexpected plan: %+v", plans)
	}
	var buf bytes.Buffer
	if err := dry.Print(&buf); err != nil || !bytes.Contains(buf.Bytes(), []byte("\"dry_run\": true")) {
		t.Fatalf("print: %v %s", err, buf.String())
	}
}

func TestWriteClient_RecordsBodyAndRedactsSecrets(t *testing.T) {
	c, dry, _ := WriteClient(false, nil)
	p := cloud_policies.NewCreateSuppressionRuleParams()
	name := "rule-x"
	p.Body = &models.SuppressionrulesCreateSuppressionRuleRequest{Name: &name}
	_, err := c.CloudPolicies.CreateSuppressionRule(p)
	if !dry.Intercepted(err) {
		t.Fatalf("want ErrDryRun, got %v", err)
	}
	pl := dry.Plans()[0]
	if pl.Method != "POST" || pl.Body == nil {
		t.Fatalf("unexpected plan: %+v", pl)
	}
	var buf bytes.Buffer
	_ = dry.Print(&buf)
	if !bytes.Contains(buf.Bytes(), []byte("rule-x")) {
		t.Fatalf("body missing from plan: %s", buf.String())
	}
}

func TestWriteClient_PassesReadsThrough(t *testing.T) {
	ft := &fakeTransport{}
	c, dry, _ := WriteClient(false, func() (*client.CrowdStrikeAPISpecification, error) {
		return client.New(ft, strfmt.Default), nil
	})
	_, err := c.CloudPolicies.GetSuppressionRules(cloud_policies.NewGetSuppressionRulesParams())
	if dry.Intercepted(err) || len(ft.ops) != 1 {
		t.Fatalf("GET should reach the real transport: err=%v ops=%v", err, ft.ops)
	}
}

func TestWriteClient_ConfirmReturnsRealClient(t *testing.T) {
	ft := &fakeTransport{}
	c, dry, err := WriteClient(true, func() (*client.CrowdStrikeAPISpecification, error) {
		return client.New(ft, strfmt.Default), nil
	})
	if err != nil || dry != nil {
		t.Fatalf("confirm: dry=%v err=%v", dry, err)
	}
	_, _ = c.CloudPolicies.DeleteSuppressionRules(cloud_policies.NewDeleteSuppressionRulesParams())
	if len(ft.ops) != 1 {
		t.Fatalf("confirmed write must be sent, ops=%v", ft.ops)
	}
}

func TestRenderPath(t *testing.T) {
	r := newRecordingRequest("DELETE", "/x/{id}/y")
	_ = r.SetPathParam("id", "a b")
	_ = r.SetQueryParam("z", "2")
	_ = r.SetQueryParam("a", "1")
	if got := r.renderPath(); got != "/x/a%20b/y?a=1&z=2" {
		t.Fatalf("renderPath = %q", got)
	}
}
