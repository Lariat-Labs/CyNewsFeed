package store

import (
	"context"
	"sort"
	"sync"
	"time"

	"cynewsfeed/internal/model"
)

// Memory is an in-process store for tests and quick local runs (STORAGE_MODE=memory).
type Memory struct {
	mu       sync.RWMutex
	feeds    map[string]model.Feed
	items    map[string]model.Item
	content  map[string]string
	rules    map[string]model.Rule
	alerts   []model.Alert
	runs     map[string]model.Run
	digests  map[string]model.Digest
	locks    map[string]bool
	chats    map[string]model.Chat
	msgs     map[string][]model.ChatMessage
	settings map[string]string
	usage    []model.UsageRecord
	reports  map[string]model.Report
}

func NewMemory() *Memory {
	return &Memory{
		feeds: map[string]model.Feed{}, items: map[string]model.Item{}, content: map[string]string{},
		rules: map[string]model.Rule{}, runs: map[string]model.Run{}, digests: map[string]model.Digest{},
		locks: map[string]bool{}, chats: map[string]model.Chat{}, msgs: map[string][]model.ChatMessage{},
		settings: map[string]string{}, reports: map[string]model.Report{},
	}
}

func (m *Memory) Init(context.Context) error { return nil }

func (m *Memory) ListFeeds(context.Context) ([]model.Feed, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]model.Feed, 0, len(m.feeds))
	for _, f := range m.feeds {
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (m *Memory) GetFeed(_ context.Context, id string) (*model.Feed, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	f, ok := m.feeds[id]
	if !ok {
		return nil, ErrNotFound
	}
	return &f, nil
}

func (m *Memory) UpsertFeed(_ context.Context, f *model.Feed) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.feeds[f.ID] = *f
	return nil
}

func (m *Memory) DeleteFeed(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.feeds, id)
	return nil
}

func (m *Memory) ItemExists(_ context.Context, id string) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.items[id]
	return ok, nil
}

func (m *Memory) PutItem(_ context.Context, it *model.Item) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *it
	if cp.Content != "" {
		m.content[cp.ID] = cp.Content
	}
	cp.Content = ""
	m.items[cp.ID] = cp
	return nil
}

func (m *Memory) GetItem(_ context.Context, id string, withContent bool) (*model.Item, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	it, ok := m.items[id]
	if !ok {
		return nil, ErrNotFound
	}
	if withContent {
		it.Content = m.content[id]
	}
	return &it, nil
}

func (m *Memory) ListItems(_ context.Context, since time.Time) ([]model.Item, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	cutoff := since.UTC().Truncate(24 * time.Hour)
	out := make([]model.Item, 0, len(m.items))
	for _, it := range m.items {
		if !it.Published.Before(cutoff) {
			out = append(out, it)
		}
	}
	SortItems(out)
	return out, nil
}

func (m *Memory) PurgeItemsBefore(_ context.Context, cutoff time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for id, it := range m.items {
		if it.Published.Before(cutoff) {
			delete(m.items, id)
			delete(m.content, id)
			n++
		}
	}
	kept := m.alerts[:0]
	for _, a := range m.alerts {
		if !a.CreatedAt.Before(cutoff) {
			kept = append(kept, a)
		}
	}
	m.alerts = kept
	return n, nil
}

func (m *Memory) ListRules(context.Context) ([]model.Rule, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]model.Rule, 0, len(m.rules))
	for _, r := range m.rules {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (m *Memory) GetRule(_ context.Context, id string) (*model.Rule, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	r, ok := m.rules[id]
	if !ok {
		return nil, ErrNotFound
	}
	return &r, nil
}

func (m *Memory) UpsertRule(_ context.Context, r *model.Rule) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rules[r.ID] = *r
	return nil
}

func (m *Memory) DeleteRule(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.rules, id)
	return nil
}

func (m *Memory) PutAlert(_ context.Context, a *model.Alert) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.alerts {
		if m.alerts[i].ID == a.ID {
			m.alerts[i] = *a
			return nil
		}
	}
	m.alerts = append(m.alerts, *a)
	return nil
}

func (m *Memory) ListAlerts(_ context.Context, since time.Time) ([]model.Alert, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []model.Alert
	for _, a := range m.alerts {
		if !a.CreatedAt.Before(since) {
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (m *Memory) PutRun(_ context.Context, r *model.Run) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.runs[r.ID] = *r
	return nil
}

func (m *Memory) ListRuns(_ context.Context, limit int) ([]model.Run, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]model.Run, 0, len(m.runs))
	for _, r := range m.runs {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Started.After(out[j].Started) })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (m *Memory) PutDigest(_ context.Context, d *model.Digest) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.digests[d.Date] = *d
	return nil
}

func (m *Memory) GetDigest(_ context.Context, date string) (*model.Digest, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	d, ok := m.digests[date]
	if !ok {
		return nil, ErrNotFound
	}
	return &d, nil
}

func (m *Memory) ListDigests(_ context.Context, limit int) ([]model.Digest, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]model.Digest, 0, len(m.digests))
	for _, d := range m.digests {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Date > out[j].Date })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (m *Memory) Lock(_ context.Context, name string) (func(), error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.locks[name] {
		return nil, ErrLocked
	}
	m.locks[name] = true
	return func() {
		m.mu.Lock()
		delete(m.locks, name)
		m.mu.Unlock()
	}, nil
}

func (m *Memory) ListChats(_ context.Context, user string) ([]model.Chat, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []model.Chat
	for _, c := range m.chats {
		if c.User == user {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UpdatedAt.After(out[j].UpdatedAt) })
	return out, nil
}

func (m *Memory) GetChat(_ context.Context, user, id string) (*model.Chat, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	c, ok := m.chats[id]
	if !ok || c.User != user {
		return nil, ErrNotFound
	}
	return &c, nil
}

func (m *Memory) PutChat(_ context.Context, c *model.Chat) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.chats[c.ID] = *c
	return nil
}

func (m *Memory) DeleteChat(_ context.Context, user, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if c, ok := m.chats[id]; ok && c.User == user {
		delete(m.chats, id)
		delete(m.msgs, id)
	}
	return nil
}

func (m *Memory) AppendChatMessage(_ context.Context, chatID string, msg *model.ChatMessage) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.msgs[chatID] = append(m.msgs[chatID], *msg)
	return nil
}

func (m *Memory) ListChatMessages(_ context.Context, chatID string) ([]model.ChatMessage, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]model.ChatMessage(nil), m.msgs[chatID]...), nil
}

func (m *Memory) GetSetting(_ context.Context, key string) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	v, ok := m.settings[key]
	if !ok {
		return "", ErrNotFound
	}
	return v, nil
}

func (m *Memory) PutSetting(_ context.Context, key, value string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.settings[key] = value
	return nil
}

func (m *Memory) PutUsage(_ context.Context, u *model.UsageRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.usage = append(m.usage, *u)
	return nil
}

func (m *Memory) ListUsage(_ context.Context, since time.Time) ([]model.UsageRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []model.UsageRecord
	for _, u := range m.usage {
		if !u.At.Before(since) {
			out = append(out, u)
		}
	}
	return out, nil
}

func (m *Memory) PutReport(_ context.Context, r *model.Report) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reports[r.ID] = *r
	return nil
}

func (m *Memory) GetReport(_ context.Context, id string) (*model.Report, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	r, ok := m.reports[id]
	if !ok {
		return nil, ErrNotFound
	}
	return &r, nil
}

func (m *Memory) ListReports(_ context.Context, limit int) ([]model.Report, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []model.Report
	for _, r := range m.reports {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}
