// Package store persists feeds, items, rules, alerts, runs and digests.
package store

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"cynewsfeed/internal/model"
)

var (
	ErrNotFound = errors.New("not found")
	ErrLocked   = errors.New("lock held by another run")
)

type Store interface {
	Init(ctx context.Context) error

	ListFeeds(ctx context.Context) ([]model.Feed, error)
	GetFeed(ctx context.Context, id string) (*model.Feed, error)
	UpsertFeed(ctx context.Context, f *model.Feed) error
	DeleteFeed(ctx context.Context, id string) error

	ItemExists(ctx context.Context, id string) (bool, error)
	PutItem(ctx context.Context, it *model.Item) error // persists Content to blob when non-empty
	GetItem(ctx context.Context, id string, withContent bool) (*model.Item, error)
	ListItems(ctx context.Context, since time.Time) ([]model.Item, error) // newest first
	PurgeItemsBefore(ctx context.Context, cutoff time.Time) (int, error)

	ListRules(ctx context.Context) ([]model.Rule, error)
	GetRule(ctx context.Context, id string) (*model.Rule, error)
	UpsertRule(ctx context.Context, r *model.Rule) error
	DeleteRule(ctx context.Context, id string) error

	PutAlert(ctx context.Context, a *model.Alert) error
	ListAlerts(ctx context.Context, since time.Time) ([]model.Alert, error)

	PutRun(ctx context.Context, r *model.Run) error
	ListRuns(ctx context.Context, limit int) ([]model.Run, error)

	PutDigest(ctx context.Context, d *model.Digest) error
	GetDigest(ctx context.Context, date string) (*model.Digest, error)
	ListDigests(ctx context.Context, limit int) ([]model.Digest, error)

	// Chats are scoped to a user (Entra principal ID, or "local").
	ListChats(ctx context.Context, user string) ([]model.Chat, error)
	GetChat(ctx context.Context, user, id string) (*model.Chat, error)
	PutChat(ctx context.Context, c *model.Chat) error
	DeleteChat(ctx context.Context, user, id string) error
	AppendChatMessage(ctx context.Context, chatID string, m *model.ChatMessage) error
	ListChatMessages(ctx context.Context, chatID string) ([]model.ChatMessage, error)

	// Settings are small JSON documents keyed by name (e.g. "prompts").
	GetSetting(ctx context.Context, key string) (string, error)
	PutSetting(ctx context.Context, key, value string) error

	PutReport(ctx context.Context, r *model.Report) error
	GetReport(ctx context.Context, id string) (*model.Report, error)
	ListReports(ctx context.Context, limit int) ([]model.Report, error)

	// Usage ledger for AI spend.
	PutUsage(ctx context.Context, u *model.UsageRecord) error
	ListUsage(ctx context.Context, since time.Time) ([]model.UsageRecord, error)

	// Lock acquires a named, auto-expiring distributed lock. The returned
	// function releases it. Returns ErrLocked when already held.
	Lock(ctx context.Context, name string) (func(), error)
}

// DayKey is the partition key for date-bucketed tables.
func DayKey(t time.Time) string { return t.UTC().Format("20060102") }

// InvTS produces a lexically-descending key so newest rows sort first.
func InvTS(t time.Time) string { return fmt.Sprintf("%019d", math.MaxInt64-t.UTC().UnixNano()) }

// FilterItems applies an ItemFilter in memory. Items must be newest-first.
func FilterItems(items []model.Item, f model.ItemFilter) []model.Item {
	q := strings.ToLower(strings.TrimSpace(f.Query))
	tag := strings.ToLower(strings.TrimSpace(f.Tag))
	minSev := -1
	if f.Severity != "" {
		minSev = model.NormalizeSeverity(f.Severity).Rank()
	}
	out := make([]model.Item, 0, len(items))
	for _, it := range items {
		if !f.Since.IsZero() && it.Published.Before(f.Since) {
			continue
		}
		if f.Category != "" && string(it.Category) != f.Category {
			continue
		}
		if f.FeedID != "" && it.FeedID != f.FeedID {
			continue
		}
		if minSev >= 0 && it.Severity.Rank() < minSev {
			continue
		}
		if f.Starred && !it.Starred {
			continue
		}
		if f.Unread && it.Read {
			continue
		}
		if f.OnlyHits && len(it.RuleHits) == 0 {
			continue
		}
		if f.RuleID != "" && !hasRule(it, f.RuleID) {
			continue
		}
		if tag != "" && !hasTag(it, tag) {
			continue
		}
		if q != "" && !matchesQuery(it, q) {
			continue
		}
		out = append(out, it)
		if f.Limit > 0 && len(out) >= f.Limit {
			break
		}
	}
	return out
}

func hasRule(it model.Item, id string) bool {
	for _, h := range it.RuleHits {
		if h.RuleID == id {
			return true
		}
	}
	return false
}

func hasTag(it model.Item, tag string) bool {
	for _, t := range it.Tags.All() {
		if strings.ToLower(t) == tag {
			return true
		}
	}
	return false
}

func matchesQuery(it model.Item, q string) bool {
	hay := strings.ToLower(strings.Join([]string{
		it.Title, it.TLDR, it.Snippet, it.WhyItMatters, it.FeedName,
		strings.Join(it.Bullets, " "), strings.Join(it.Tags.All(), " "),
	}, " "))
	for _, term := range strings.Fields(q) {
		if !strings.Contains(hay, term) {
			return false
		}
	}
	return true
}

// SortItems sorts newest first.
func SortItems(items []model.Item) {
	sort.SliceStable(items, func(i, j int) bool { return items[i].Published.After(items[j].Published) })
}
