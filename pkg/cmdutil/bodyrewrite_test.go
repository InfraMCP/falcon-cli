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
	"encoding/json"
	"testing"
)

func TestStringifyResourceFields_Object(t *testing.T) {
	in := []byte(`{"meta":{"x":1},"resources":[{"id":"a","remediation_plan":{"steps":["s1"]}},{"id":"b","remediation_plan":"plain"}]}`)
	out, err := StringifyResourceFields("remediation_plan")(in)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Meta      map[string]int `json:"meta"`
		Resources []struct {
			ID   string `json:"id"`
			Plan string `json:"remediation_plan"`
		} `json:"resources"`
	}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("rewritten body does not decode into string field: %v", err)
	}
	if got.Resources[0].Plan != `{"steps":["s1"]}` || got.Resources[1].Plan != "plain" || got.Meta["x"] != 1 {
		t.Fatalf("unexpected rewrite: %+v", got)
	}
}

func TestStringifyResourceFields_NoChange(t *testing.T) {
	in := []byte(`{"resources":[{"id":"a"}]}`)
	out, err := StringifyResourceFields("remediation_plan")(in)
	if err != nil || string(out) != string(in) {
		t.Fatalf("want unchanged body, got %s (%v)", out, err)
	}
}

func TestStringifyResourceFields_BadJSON(t *testing.T) {
	if _, err := StringifyResourceFields("x")([]byte("nope")); err == nil {
		t.Fatal("want error for invalid JSON")
	}
}
