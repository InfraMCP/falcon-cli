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

package codesecurity

import (
	"testing"

	"github.com/crowdstrike/falcon-cli/internal/testutil"
	"github.com/crowdstrike/falcon-cli/pkg/cmdutil"
	"github.com/crowdstrike/falcon-cli/pkg/factory"
)

func TestWiring(t *testing.T) {
	cmd := NewCodeSecurityCmd(&factory.Factory{})
	testutil.AssertHasSubcommands(t, testutil.SubcommandNames(cmd),
		[]string{"connections", "repositories", "exclusions", "branch-configs", "pull-jobs"})
	repos := testutil.FindSub(cmd, "repositories")
	testutil.AssertHasSubcommands(t, testutil.SubcommandNames(repos), []string{"list", "branches", "aggregate"})
}

func TestDynamicTable_PreferredFirstThenScalarsCapped(t *testing.T) {
	items := []map[string]any{{"zeta": "z", "name": "repo", "id": "1", "nested": map[string]any{"a": 1},
		"b": 1.0, "c": true, "d": "x", "e": "y", "f": "w"}}
	def := dynamicTable(items, []string{"id", "name", "missing"}, false)
	if len(def.Headers) != maxAutoColumns || def.Headers[0] != "ID" || def.Headers[1] != "NAME" {
		t.Fatalf("headers = %v", def.Headers)
	}
	for _, h := range def.Headers {
		if h == "NESTED" || h == "MISSING" {
			t.Fatalf("unexpected column %s in %v", h, def.Headers)
		}
	}
	row := def.RowFunc(items[0])
	if row[0] != "1" || row[1] != "repo" {
		t.Fatalf("row = %v", row)
	}
}

func TestDynamicTable_AllColumnsWhenRequested(t *testing.T) {
	items := []map[string]any{{"id": "1", "nested": map[string]any{"a": 1}}}
	def := dynamicTable(items, nil, true)
	testutil.AssertRow(t, def.RowFunc(items[0]), []string{"1", `{"a":1}`})
}

func TestCellString(t *testing.T) {
	cases := map[string]any{"": nil, "s": "s", "true": true, "3": 3.0, "a,b": []any{"a", "b"}}
	for want, in := range cases {
		if got := cellString(in); got != want {
			t.Errorf("cellString(%v) = %q, want %q", in, got, want)
		}
	}
}

func TestBranchConfigItems_TagsSource(t *testing.T) {
	body := []byte(`{"resources":[{"id":"own1"}],"inherited_resources":[{"id":"inh1"}]}`)
	items, err := branchConfigItems(body)
	if err != nil || len(items) != 2 || items[0]["source"] != "own" || items[1]["source"] != "inherited" {
		t.Fatalf("items = %v err = %v", items, err)
	}
}

func TestRawResources_Shapes(t *testing.T) {
	for body, want := range map[string]int{
		`{"resources":[{"a":1},{"a":2}]}`: 2,
		`{"resources":{"a":1}}`:           1,
		`{"resources":null}`:              0,
		`{"meta":{}}`:                     0,
		`{"resources":["x"]}`:             1,
	} {
		got, err := cmdutil.RawResources([]byte(body), "")
		if err != nil || len(got) != want {
			t.Errorf("%s: got %d (%v), want %d", body, len(got), err, want)
		}
	}
}

func TestRequiredFlags(t *testing.T) {
	for _, args := range [][]string{
		{"connections", "get"}, {"repositories", "branches"}, {"repositories", "aggregate"},
		{"exclusions", "list"}, {"branch-configs", "get"}, {"pull-jobs", "get"},
	} {
		f, buf := testutil.FactoryWithBuffer()
		root := NewCodeSecurityCmd(f)
		root.SetArgs(args)
		root.SetOut(buf)
		root.SetErr(buf)
		if err := root.Execute(); err == nil {
			t.Errorf("%v: expected missing-required-flag error", args)
		}
	}
}
