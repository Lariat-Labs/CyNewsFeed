package detect

import (
	"testing"

	"cynewsfeed/internal/model"
)

func TestNormalize(t *testing.T) {
	ds := Normalize([]model.Detection{
		{Format: "sigma", Query: "```yaml\ntitle: x\nlogsource:\n  product: windows\ndetection:\n  sel:\n    Image|endswith: '\\\\w3wp.exe'\n  condition: sel\n```"},
		{Format: "sigma", Query: "title: x\ndetection:\n  sel: {a: 1}"},
		{Format: "kql", Query: "let ips = dynamic([\"1.2.3.4\"]);\nDeviceNetworkEvents | where RemoteIP in (ips)"},
		{Format: "kql", Query: "DeviceNetworkEvents | where (RemoteIP == \"1.2.3.4\""},
		{Format: "yara", Query: "rule Bad { strings: $a = \"x\" condition: $a }"},
		{Format: "spl", Query: "  "},
	})
	if len(ds) != 5 {
		t.Fatalf("empty query should be dropped: %d", len(ds))
	}
	want := []bool{true, false, true, false, true}
	for i, d := range ds {
		if d.Valid != want[i] {
			t.Errorf("%d %s valid=%v issue=%q", i, d.Format, d.Valid, d.Issue)
		}
	}
	if ds[0].Query[:6] != "title:" {
		t.Errorf("fence not stripped: %q", ds[0].Query)
	}
}
