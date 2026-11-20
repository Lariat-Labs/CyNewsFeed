package ioc

import (
	"testing"

	"cynewsfeed/internal/model"
)

func has(l []model.IOC, t, v string) bool {
	for _, i := range l {
		if i.Type == t && i.Value == v {
			return true
		}
	}
	return false
}

func TestExtractDefanged(t *testing.T) {
	text := `The loader beacons to hxxps://update-check[.]xyz/gate.php and 185.220.101[.]45,
	drops a7f3c2e1b0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3 and mails ops[@]evil-corp[.]ru.
	C2 also seen at login-microsoft-secure[.]com.`
	got := Extract(nil, text)
	for _, want := range []model.IOC{
		{Type: "url", Value: "https://update-check.xyz/gate.php"},
		{Type: "ip", Value: "185.220.101.45"},
		{Type: "sha256", Value: "a7f3c2e1b0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3"},
		{Type: "email", Value: "ops@evil-corp.ru"},
		{Type: "domain", Value: "login-microsoft-secure.com"},
	} {
		if !has(got, want.Type, want.Value) {
			t.Errorf("missing %v in %v", want, got)
		}
	}
}

func TestExtractAvoidsFalsePositives(t *testing.T) {
	text := `Microsoft released Windows 10.0.19045.1 and PAN-OS v11.1.2.3 fixes; see https://www.microsoft.com/security
	and the vendor site acme.com. Internal hosts 10.0.0.5 and 192.168.1.1 were targeted. Run update.exe or read window.location.
	Reported by BleepingComputer at bleepingcomputer.com.`
	got := Extract([]string{"www.bleepingcomputer.com"}, text)
	if len(got) != 0 {
		t.Fatalf("expected no IOCs, got %v", got)
	}
}

func TestDefangRoundTrip(t *testing.T) {
	if d := Defang("url", "https://evil.xyz/a"); d != "hxxps://evil[.]xyz/a" {
		t.Fatalf("defang = %s", d)
	}
	if r := Refang("hxxps://evil[.]xyz/a"); r != "https://evil.xyz/a" {
		t.Fatalf("refang = %s", r)
	}
}

func TestMerge(t *testing.T) {
	m := Merge([]model.IOC{{Type: "ip", Value: "1.2.3.4"}}, []model.IOC{{Type: "IP", Value: "1.2.3.4"}, {Type: "domain", Value: "bad[.]xyz"}, {Type: "bogus", Value: "x"}})
	if len(m) != 2 || m[1].Value != "bad.xyz" {
		t.Fatalf("merge = %v", m)
	}
}

func TestFileNamesInDefangedArticle(t *testing.T) {
	text := `The loader drops start.exe, jli.dll and tasks.json via node.js prebuild.js, reads com.zoom.plist and logs.dat,
	then beacons to cdn-update[.]top and hxxps://login-portal[.]example-bad[.]com/a. Mail from ops[@]evil[.]ru.
	It authenticates via login.microsoftonline.com and runs cmd.exe. Version 10.0.19045.1 is affected.`
	got := Extract(nil, text)
	want := map[string]bool{"domain|cdn-update.top": true, "url|https://login-portal.example-bad.com/a": true, "email|ops@evil.ru": true}
	for _, i := range got {
		if !want[i.Type+"|"+i.Value] {
			t.Errorf("unexpected IOC %v", i)
		}
		delete(want, i.Type+"|"+i.Value)
	}
	for k := range want {
		t.Errorf("missing %s", k)
	}
}
