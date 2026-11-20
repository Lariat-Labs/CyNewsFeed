package frameworks

import (
	"testing"

	"cynewsfeed/internal/model"
)

func TestExtractAndClean(t *testing.T) {
	at, al, ow := ExtractExplicit("Initial access via T1190 then T1059.001; ATLAS AML.T0051 prompt injection (LLM01:2025) and LLM06. Not T99 or AML.T12.")
	if len(at) != 2 || at[1].ID != "T1059.001" {
		t.Fatalf("attack %v", at)
	}
	if len(al) != 1 || al[0].ID != "AML.T0051" {
		t.Fatalf("atlas %v", al)
	}
	if len(ow) != 2 || ow[0] != "LLM01" || ow[1] != "LLM06" {
		t.Fatalf("owasp %v", ow)
	}
	c := Clean([]model.Technique{{ID: "t1566"}, {ID: "bogus"}, {ID: "T1566", Name: "Phishing"}}, false)
	if len(c) != 1 || c[0].ID != "T1566" {
		t.Fatalf("clean %v", c)
	}
	m := Merge([]model.Technique{{ID: "T1566"}}, []model.Technique{{ID: "T1566", Name: "Phishing", Tactic: "Initial Access"}})
	if len(m) != 1 || m[0].Name != "Phishing" || m[0].Tactic != "Initial Access" {
		t.Fatalf("merge %v", m)
	}
	if got := CleanOWASP([]string{"llm11", "LLM10", "llm03"}); len(got) != 2 || got[0] != "LLM03" {
		t.Fatalf("owasp clean %v", got)
	}
}
