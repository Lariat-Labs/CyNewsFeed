package store

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"cynewsfeed/internal/model"
)

// Integration test against Azurite. Run with:
//
//	docker run -d -p 10000-10002:10000-10002 mcr.microsoft.com/azure-storage/azurite
//	AZURITE=1 go test ./internal/store/
const azuriteConn = "DefaultEndpointsProtocol=http;AccountName=devstoreaccount1;AccountKey=Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==;BlobEndpoint=http://127.0.0.1:10000/devstoreaccount1;TableEndpoint=http://127.0.0.1:10002/devstoreaccount1;"

func TestAzureStore(t *testing.T) {
	if os.Getenv("AZURITE") == "" {
		t.Skip("set AZURITE=1 with Azurite running to run this test")
	}
	ctx := context.Background()
	prefix := fmt.Sprintf("t%d", time.Now().UnixNano()%1e9)
	a, err := NewAzure(azuriteConn, "", prefix, prefix)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Init(ctx); err != nil {
		t.Fatal(err)
	}
	if err := a.Init(ctx); err != nil { // idempotent
		t.Fatal(err)
	}

	// feeds keep server-only fields
	f := &model.Feed{ID: "f1", Name: "Feed", URL: "https://x", Kind: model.FeedRSS, Enabled: true, ETag: `"e1"`, LastModified: "lm"}
	if err := a.UpsertFeed(ctx, f); err != nil {
		t.Fatal(err)
	}
	got, err := a.GetFeed(ctx, "f1")
	if err != nil || got.ETag != `"e1"` || got.LastModified != "lm" {
		t.Fatalf("feed %+v err %v", got, err)
	}
	fs, _ := a.ListFeeds(ctx)
	if len(fs) != 1 || fs[0].ETag != `"e1"` {
		t.Fatalf("list feeds %+v", fs)
	}

	// items across partitions, newest first, content in blob
	now := time.Now().UTC()
	old := &model.Item{ID: "old", Title: "Old", Published: now.AddDate(0, 0, -100), Severity: model.SevLow}
	recent := &model.Item{ID: "new", Title: "New", Published: now, Severity: model.SevHigh, Content: "full body text", Tags: model.Tags{CVEs: []string{"CVE-1"}}}
	mid := &model.Item{ID: "mid", Title: "Mid", Published: now.AddDate(0, 0, -2)}
	for _, it := range []*model.Item{old, recent, mid} {
		if err := a.PutItem(ctx, it); err != nil {
			t.Fatal(err)
		}
	}
	if ok, _ := a.ItemExists(ctx, "new"); !ok {
		t.Fatal("expected exists")
	}
	if ok, _ := a.ItemExists(ctx, "nope"); ok {
		t.Fatal("expected not exists")
	}
	it, err := a.GetItem(ctx, "new", true)
	if err != nil || it.Content != "full body text" || it.Tags.CVEs[0] != "CVE-1" {
		t.Fatalf("get item %+v err %v", it, err)
	}
	list, _ := a.ListItems(ctx, now.AddDate(0, 0, -7))
	if len(list) != 2 || list[0].ID != "new" || list[1].ID != "mid" || list[0].Content != "" {
		t.Fatalf("list items %+v", list)
	}
	n, err := a.PurgeItemsBefore(ctx, now.AddDate(0, 0, -90))
	if err != nil || n != 1 {
		t.Fatalf("purge n=%d err=%v", n, err)
	}
	if _, err := a.GetItem(ctx, "old", false); !errors.Is(err, ErrNotFound) {
		t.Fatalf("old item should be gone: %v", err)
	}

	// rules, alerts, runs, digests
	_ = a.UpsertRule(ctx, &model.Rule{ID: "r1", Name: "Rule", Keywords: []string{"k"}})
	if rs, _ := a.ListRules(ctx); len(rs) != 1 || rs[0].Keywords[0] != "k" {
		t.Fatalf("rules %+v", rs)
	}
	_ = a.PutAlert(ctx, &model.Alert{ID: "r1_new", RuleID: "r1", CreatedAt: now})
	if as, _ := a.ListAlerts(ctx, now.Add(-time.Hour)); len(as) != 1 {
		t.Fatalf("alerts %+v", as)
	}
	_ = a.PutRun(ctx, &model.Run{ID: InvTS(now.Add(-time.Minute)), Kind: "aggregate", Started: now.Add(-time.Minute)})
	_ = a.PutRun(ctx, &model.Run{ID: InvTS(now), Kind: "digest", Started: now})
	if runs, _ := a.ListRuns(ctx, 1); len(runs) != 1 || runs[0].Kind != "digest" {
		t.Fatalf("runs %+v", runs)
	}
	_ = a.PutDigest(ctx, &model.Digest{Date: "2026-11-18", Headline: "a"})
	_ = a.PutDigest(ctx, &model.Digest{Date: "2026-11-19", Headline: "b"})
	if ds, _ := a.ListDigests(ctx, 10); len(ds) != 2 || ds[0].Date != "2026-11-19" {
		t.Fatalf("digests %+v", ds)
	}
	if d, err := a.GetDigest(ctx, "2026-11-18"); err != nil || d.Headline != "a" {
		t.Fatalf("digest %+v err %v", d, err)
	}

	// chats: per-user isolation, ordered messages in blobs, delete cascades
	c := &model.Chat{ID: "chat1", User: "user-a@x", Title: "T", CreatedAt: now, UpdatedAt: now}
	if err := a.PutChat(ctx, c); err != nil {
		t.Fatal(err)
	}
	for i, role := range []string{"user", "assistant", "user"} {
		if err := a.AppendChatMessage(ctx, "chat1", &model.ChatMessage{Seq: i, Role: role, Text: fmt.Sprint(i), Native: []byte(`["x"]`)}); err != nil {
			t.Fatal(err)
		}
	}
	if cs, _ := a.ListChats(ctx, "user-a@x"); len(cs) != 1 {
		t.Fatalf("chats %+v", cs)
	}
	if cs, _ := a.ListChats(ctx, "user-b@x"); len(cs) != 0 {
		t.Fatal("chats leaked across users")
	}
	if _, err := a.GetChat(ctx, "user-b@x", "chat1"); !errors.Is(err, ErrNotFound) {
		t.Fatal("other user can read chat")
	}
	ms, err := a.ListChatMessages(ctx, "chat1")
	if err != nil || len(ms) != 3 || ms[2].Text != "2" || string(ms[1].Native) != `["x"]` {
		t.Fatalf("messages %+v err %v", ms, err)
	}
	_ = a.DeleteChat(ctx, "user-b@x", "chat1") // not the owner: no-op
	if ms, _ := a.ListChatMessages(ctx, "chat1"); len(ms) != 3 {
		t.Fatal("non-owner deleted messages")
	}
	_ = a.DeleteChat(ctx, "user-a@x", "chat1")
	if ms, _ := a.ListChatMessages(ctx, "chat1"); len(ms) != 0 {
		t.Fatal("messages not deleted")
	}
	if err := a.PutSetting(ctx, "prompts", `{"cve":"x"}`); err != nil {
		t.Fatal(err)
	}
	if v, err := a.GetSetting(ctx, "prompts"); err != nil || v != `{"cve":"x"}` {
		t.Fatalf("setting %q %v", v, err)
	}

	// reports overwrite per period id; usage ledger
	_ = a.PutReport(ctx, &model.Report{ID: "2026-W46", Title: "old", PeriodEnd: now.AddDate(0, 0, -7), CreatedAt: now})
	_ = a.PutReport(ctx, &model.Report{ID: "2026-W47", Title: "v1", PeriodEnd: now, CreatedAt: now})
	_ = a.PutReport(ctx, &model.Report{ID: "2026-W47", Title: "v2", PeriodEnd: now, CreatedAt: now})
	if rs, _ := a.ListReports(ctx, 10); len(rs) != 2 || rs[0].ID != "2026-W47" || rs[0].Title != "v2" {
		t.Fatalf("reports %+v", rs)
	}
	if r, err := a.GetReport(ctx, "2026-W46"); err != nil || r.Title != "old" {
		t.Fatalf("get report %v %v", r, err)
	}
	_ = a.PutUsage(ctx, &model.UsageRecord{ID: "u1", Kind: "chat", At: now, TokenUsage: model.TokenUsage{CostUSD: 0.12}})
	if us, _ := a.ListUsage(ctx, now.Add(-time.Hour)); len(us) != 1 || us[0].CostUSD != 0.12 {
		t.Fatalf("usage %+v", us)
	}

	// distributed lock
	unlock, err := a.Lock(ctx, "agg")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Lock(ctx, "agg"); !errors.Is(err, ErrLocked) {
		t.Fatalf("want ErrLocked, got %v", err)
	}
	unlock()
	unlock2, err := a.Lock(ctx, "agg")
	if err != nil {
		t.Fatalf("relock: %v", err)
	}
	unlock2()
}
