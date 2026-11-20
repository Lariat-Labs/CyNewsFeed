package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/data/aztables"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/bloberror"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/lease"

	"cynewsfeed/internal/model"
)

// Azure stores state in Azure Table Storage (entities) and Blob Storage
// (article text, locks). Each entity keeps its full JSON document in a "Data"
// property plus a few denormalised columns for browsing in Storage Explorer.
type Azure struct {
	svc       *aztables.ServiceClient
	blobs     *azblob.Client
	container string
	t         map[string]*aztables.Client
}

const (
	tFeeds   = "feeds"
	tItems   = "items"
	tIndex   = "itemindex"
	tRules   = "rules"
	tAlerts  = "alerts"
	tRuns    = "runs"
	tDigests = "digests"
	tChats   = "chats"
	tSetting = "settings"
	tUsage   = "usage"
	tReports = "reports"
)

// NewAzure builds a store from a connection string (Azurite/local) or an
// account name using DefaultAzureCredential (managed identity in Azure).
func NewAzure(connString, account, tablePrefix, container string) (*Azure, error) {
	a := &Azure{container: container, t: map[string]*aztables.Client{}}
	var err error
	if connString != "" {
		if a.svc, err = aztables.NewServiceClientFromConnectionString(connString, nil); err != nil {
			return nil, fmt.Errorf("tables client: %w", err)
		}
		if a.blobs, err = azblob.NewClientFromConnectionString(connString, nil); err != nil {
			return nil, fmt.Errorf("blob client: %w", err)
		}
	} else {
		cred, cerr := azidentity.NewDefaultAzureCredential(nil)
		if cerr != nil {
			return nil, fmt.Errorf("azure credential: %w", cerr)
		}
		if a.svc, err = aztables.NewServiceClient(fmt.Sprintf("https://%s.table.core.windows.net/", account), cred, nil); err != nil {
			return nil, fmt.Errorf("tables client: %w", err)
		}
		if a.blobs, err = azblob.NewClient(fmt.Sprintf("https://%s.blob.core.windows.net/", account), cred, nil); err != nil {
			return nil, fmt.Errorf("blob client: %w", err)
		}
	}
	for _, name := range []string{tFeeds, tItems, tIndex, tRules, tAlerts, tRuns, tDigests, tChats, tSetting, tUsage, tReports} {
		a.t[name] = a.svc.NewClient(tablePrefix + name)
	}
	return a, nil
}

func (a *Azure) Init(ctx context.Context) error {
	for _, c := range a.t {
		if _, err := c.CreateTable(ctx, nil); err != nil && !isCode(err, http.StatusConflict) {
			return fmt.Errorf("create table: %w", err)
		}
	}
	if _, err := a.blobs.CreateContainer(ctx, a.container, nil); err != nil && !bloberror.HasCode(err, bloberror.ContainerAlreadyExists) {
		return fmt.Errorf("create container: %w", err)
	}
	return nil
}

// ---- generic entity helpers ----

type entity struct {
	PartitionKey string
	RowKey       string
	Data         string
	Title        string `json:",omitempty"`
	Category     string `json:",omitempty"`
	Severity     string `json:",omitempty"`
	Ref          string `json:",omitempty"`
}

func (a *Azure) upsert(ctx context.Context, table string, e entity, doc any) error {
	if doc != nil {
		b, err := json.Marshal(doc)
		if err != nil {
			return err
		}
		e.Data = string(b)
	}
	// Table string properties are limited to 64 KiB (32K UTF-16 chars).
	if len(e.Data) > 60000 {
		return fmt.Errorf("%s entity %s/%s too large (%d bytes)", table, e.PartitionKey, e.RowKey, len(e.Data))
	}
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	_, err = a.t[table].UpsertEntity(ctx, b, &aztables.UpsertEntityOptions{UpdateMode: aztables.UpdateModeReplace})
	return err
}

func (a *Azure) get(ctx context.Context, table, pk, rk string) (*entity, error) {
	resp, err := a.t[table].GetEntity(ctx, pk, rk, nil)
	if err != nil {
		if isCode(err, http.StatusNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	var e entity
	if err := json.Unmarshal(resp.Value, &e); err != nil {
		return nil, err
	}
	return &e, nil
}

func (a *Azure) del(ctx context.Context, table, pk, rk string) error {
	_, err := a.t[table].DeleteEntity(ctx, pk, rk, nil)
	if err != nil && isCode(err, http.StatusNotFound) {
		return nil
	}
	return err
}

func (a *Azure) query(ctx context.Context, table, filter string, top int, fn func(entity) bool) error {
	opts := &aztables.ListEntitiesOptions{}
	if filter != "" {
		opts.Filter = to.Ptr(filter)
	}
	if top > 0 && top < 1000 {
		opts.Top = to.Ptr(int32(top))
	}
	pager := a.t[table].NewListEntitiesPager(opts)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return err
		}
		for _, raw := range page.Entities {
			var e entity
			if err := json.Unmarshal(raw, &e); err != nil {
				return err
			}
			if !fn(e) {
				return nil
			}
		}
	}
	return nil
}

func queryAll[T any](ctx context.Context, a *Azure, table, filter string, top int) ([]T, error) {
	var out []T
	var decodeErr error
	err := a.query(ctx, table, filter, top, func(e entity) bool {
		var v T
		if err := json.Unmarshal([]byte(e.Data), &v); err != nil {
			decodeErr = err
			return false
		}
		out = append(out, v)
		return top <= 0 || len(out) < top
	})
	if err == nil {
		err = decodeErr
	}
	return out, err
}

func decode[T any](e *entity) (*T, error) {
	var v T
	if err := json.Unmarshal([]byte(e.Data), &v); err != nil {
		return nil, err
	}
	return &v, nil
}

func isCode(err error, status int) bool {
	var re *azcore.ResponseError
	return errors.As(err, &re) && re.StatusCode == status
}

func odataQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

// ---- feeds ----

func (a *Azure) ListFeeds(ctx context.Context) ([]model.Feed, error) {
	docs, err := queryAll[feedDoc](ctx, a, tFeeds, "PartitionKey eq 'feed'", 0)
	out := make([]model.Feed, 0, len(docs))
	for _, d := range docs {
		out = append(out, d.feed())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, err
}

func (a *Azure) GetFeed(ctx context.Context, id string) (*model.Feed, error) {
	e, err := a.get(ctx, tFeeds, "feed", id)
	if err != nil {
		return nil, err
	}
	d, err := decode[feedDoc](e)
	if err != nil {
		return nil, err
	}
	f := d.feed()
	return &f, nil
}

// feedDoc includes fields hidden from the public JSON (etag etc.).
type feedDoc struct {
	model.Feed
	ETag         string `json:"etag,omitempty"`
	LastModified string `json:"lastModifiedHdr,omitempty"`
}

func (d feedDoc) feed() model.Feed {
	f := d.Feed
	f.ETag, f.LastModified = d.ETag, d.LastModified
	return f
}

func (a *Azure) UpsertFeed(ctx context.Context, f *model.Feed) error {
	return a.upsert(ctx, tFeeds, entity{PartitionKey: "feed", RowKey: f.ID, Title: f.Name, Category: string(f.Category)},
		feedDoc{Feed: *f, ETag: f.ETag, LastModified: f.LastModified})
}

func (a *Azure) DeleteFeed(ctx context.Context, id string) error {
	return a.del(ctx, tFeeds, "feed", id)
}

// ---- items ----

type indexRef struct{ PK, RK string }

func (a *Azure) ItemExists(ctx context.Context, id string) (bool, error) {
	_, err := a.get(ctx, tIndex, "id", id)
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	return err == nil, err
}

func itemKeys(it *model.Item) (string, string) {
	return DayKey(it.Published), InvTS(it.Published) + "_" + it.ID
}

func (a *Azure) PutItem(ctx context.Context, it *model.Item) error {
	pk, rk := itemKeys(it)
	if it.Content != "" {
		if _, err := a.blobs.UploadBuffer(ctx, a.container, "raw/"+it.ID+".txt", []byte(it.Content), nil); err != nil {
			return fmt.Errorf("upload content: %w", err)
		}
	}
	cp := *it
	cp.Content = ""
	if err := a.upsert(ctx, tItems, entity{PartitionKey: pk, RowKey: rk, Title: cp.Title,
		Category: string(cp.Category), Severity: string(cp.Severity)}, cp); err != nil {
		return err
	}
	return a.upsert(ctx, tIndex, entity{PartitionKey: "id", RowKey: it.ID, Ref: pk + "|" + rk}, indexRef{pk, rk})
}

func (a *Azure) GetItem(ctx context.Context, id string, withContent bool) (*model.Item, error) {
	ie, err := a.get(ctx, tIndex, "id", id)
	if err != nil {
		return nil, err
	}
	ref, err := decode[indexRef](ie)
	if err != nil {
		return nil, err
	}
	e, err := a.get(ctx, tItems, ref.PK, ref.RK)
	if err != nil {
		return nil, err
	}
	it, err := decode[model.Item](e)
	if err != nil {
		return nil, err
	}
	if withContent {
		if resp, err := a.blobs.DownloadStream(ctx, a.container, "raw/"+id+".txt", nil); err == nil {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			resp.Body.Close()
			it.Content = string(b)
		}
	}
	return it, nil
}

func (a *Azure) ListItems(ctx context.Context, since time.Time) ([]model.Item, error) {
	out, err := queryAll[model.Item](ctx, a, tItems, "PartitionKey ge "+odataQuote(DayKey(since)), 0)
	if err != nil {
		return nil, err
	}
	SortItems(out)
	return out, nil
}

func (a *Azure) PurgeItemsBefore(ctx context.Context, cutoff time.Time) (int, error) {
	filter := "PartitionKey lt " + odataQuote(DayKey(cutoff))
	type key struct{ pk, rk, id string }
	var keys []key
	err := a.query(ctx, tItems, filter, 0, func(e entity) bool {
		var it struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal([]byte(e.Data), &it)
		keys = append(keys, key{e.PartitionKey, e.RowKey, it.ID})
		return true
	})
	if err != nil {
		return 0, err
	}
	for _, k := range keys {
		if err := a.del(ctx, tItems, k.pk, k.rk); err != nil {
			return 0, err
		}
		if k.id != "" {
			_ = a.del(ctx, tIndex, "id", k.id)
			if _, err := a.blobs.DeleteBlob(ctx, a.container, "raw/"+k.id+".txt", nil); err != nil && !bloberror.HasCode(err, bloberror.BlobNotFound) {
				slog.Warn("purge blob", "id", k.id, "err", err)
			}
		}
	}
	// Alerts share the date partitioning.
	var akeys []key
	_ = a.query(ctx, tAlerts, filter, 0, func(e entity) bool {
		akeys = append(akeys, key{pk: e.PartitionKey, rk: e.RowKey})
		return true
	})
	for _, k := range akeys {
		_ = a.del(ctx, tAlerts, k.pk, k.rk)
	}
	return len(keys), nil
}

// ---- rules ----

func (a *Azure) ListRules(ctx context.Context) ([]model.Rule, error) {
	out, err := queryAll[model.Rule](ctx, a, tRules, "PartitionKey eq 'rule'", 0)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, err
}

func (a *Azure) GetRule(ctx context.Context, id string) (*model.Rule, error) {
	e, err := a.get(ctx, tRules, "rule", id)
	if err != nil {
		return nil, err
	}
	return decode[model.Rule](e)
}

func (a *Azure) UpsertRule(ctx context.Context, r *model.Rule) error {
	return a.upsert(ctx, tRules, entity{PartitionKey: "rule", RowKey: r.ID, Title: r.Name}, r)
}

func (a *Azure) DeleteRule(ctx context.Context, id string) error {
	return a.del(ctx, tRules, "rule", id)
}

// ---- alerts ----

func (a *Azure) PutAlert(ctx context.Context, al *model.Alert) error {
	return a.upsert(ctx, tAlerts, entity{PartitionKey: DayKey(al.CreatedAt),
		RowKey: InvTS(al.CreatedAt) + "_" + al.ID, Title: al.Title, Severity: string(al.Severity)}, al)
}

func (a *Azure) ListAlerts(ctx context.Context, since time.Time) ([]model.Alert, error) {
	out, err := queryAll[model.Alert](ctx, a, tAlerts, "PartitionKey ge "+odataQuote(DayKey(since)), 0)
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, err
}

// ---- runs ----

func (a *Azure) PutRun(ctx context.Context, r *model.Run) error {
	return a.upsert(ctx, tRuns, entity{PartitionKey: "run", RowKey: r.ID, Title: r.Kind}, r)
}

func (a *Azure) ListRuns(ctx context.Context, limit int) ([]model.Run, error) {
	return queryAll[model.Run](ctx, a, tRuns, "PartitionKey eq 'run'", limit)
}

// ---- digests ----

func (a *Azure) PutDigest(ctx context.Context, d *model.Digest) error {
	// RowKey inverted so the newest digest is listed first.
	return a.upsert(ctx, tDigests, entity{PartitionKey: "digest", RowKey: invDate(d.Date), Title: d.Headline}, d)
}

func (a *Azure) GetDigest(ctx context.Context, date string) (*model.Digest, error) {
	e, err := a.get(ctx, tDigests, "digest", invDate(date))
	if err != nil {
		return nil, err
	}
	return decode[model.Digest](e)
}

func (a *Azure) ListDigests(ctx context.Context, limit int) ([]model.Digest, error) {
	return queryAll[model.Digest](ctx, a, tDigests, "PartitionKey eq 'digest'", limit)
}

func invDate(date string) string {
	t, err := time.Parse("2006-01-02", date)
	if err != nil {
		return date
	}
	return InvTS(t)
}

// ---- locks (blob leases, renewed in the background) ----

func (a *Azure) Lock(ctx context.Context, name string) (func(), error) {
	bc := a.blobs.ServiceClient().NewContainerClient(a.container).NewBlockBlobClient("locks/" + name)
	if _, err := bc.GetProperties(ctx, nil); err != nil {
		if !bloberror.HasCode(err, bloberror.BlobNotFound) {
			return nil, err
		}
		if _, err := bc.Upload(ctx, nopCloser{bytes.NewReader(nil)}, nil); err != nil && !bloberror.HasCode(err, bloberror.LeaseIDMissing) {
			return nil, fmt.Errorf("create lock blob: %w", err)
		}
	}
	lc, err := lease.NewBlobClient(bc, nil)
	if err != nil {
		return nil, err
	}
	if _, err := lc.AcquireLease(ctx, 60, nil); err != nil {
		if bloberror.HasCode(err, bloberror.LeaseAlreadyPresent) {
			return nil, ErrLocked
		}
		return nil, fmt.Errorf("acquire lease: %w", err)
	}
	stop := make(chan struct{})
	var once sync.Once
	go func() {
		t := time.NewTicker(20 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				if _, err := lc.RenewLease(context.Background(), nil); err != nil {
					slog.Warn("lock renew failed", "lock", name, "err", err)
				}
			}
		}
	}()
	return func() {
		once.Do(func() {
			close(stop)
			if _, err := lc.ReleaseLease(context.Background(), nil); err != nil {
				slog.Warn("lock release failed", "lock", name, "err", err)
			}
		})
	}, nil
}

type nopCloser struct{ *bytes.Reader }

func (nopCloser) Close() error { return nil }

// ---- chats (metadata in Tables, messages as blobs: chats/{id}/{seq}.json) ----

// userKey makes an Entra principal ID safe for use as a PartitionKey.
func userKey(user string) string {
	sum := sha256.Sum256([]byte(user))
	return hex.EncodeToString(sum[:12])
}

func (a *Azure) ListChats(ctx context.Context, user string) ([]model.Chat, error) {
	out, err := queryAll[model.Chat](ctx, a, tChats, "PartitionKey eq "+odataQuote(userKey(user)), 0)
	sort.Slice(out, func(i, j int) bool { return out[i].UpdatedAt.After(out[j].UpdatedAt) })
	return out, err
}

func (a *Azure) GetChat(ctx context.Context, user, id string) (*model.Chat, error) {
	e, err := a.get(ctx, tChats, userKey(user), id)
	if err != nil {
		return nil, err
	}
	return decode[model.Chat](e)
}

func (a *Azure) PutChat(ctx context.Context, c *model.Chat) error {
	return a.upsert(ctx, tChats, entity{PartitionKey: userKey(c.User), RowKey: c.ID, Title: c.Title}, c)
}

func (a *Azure) DeleteChat(ctx context.Context, user, id string) error {
	if _, err := a.GetChat(ctx, user, id); err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		return err
	}
	prefix := "chats/" + id + "/"
	pager := a.blobs.NewListBlobsFlatPager(a.container, &azblob.ListBlobsFlatOptions{Prefix: &prefix})
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return err
		}
		for _, b := range page.Segment.BlobItems {
			_, _ = a.blobs.DeleteBlob(ctx, a.container, *b.Name, nil)
		}
	}
	return a.del(ctx, tChats, userKey(user), id)
}

func (a *Azure) AppendChatMessage(ctx context.Context, chatID string, m *model.ChatMessage) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	_, err = a.blobs.UploadBuffer(ctx, a.container, fmt.Sprintf("chats/%s/%06d.json", chatID, m.Seq), b, nil)
	return err
}

func (a *Azure) ListChatMessages(ctx context.Context, chatID string) ([]model.ChatMessage, error) {
	prefix := "chats/" + chatID + "/"
	var names []string
	pager := a.blobs.NewListBlobsFlatPager(a.container, &azblob.ListBlobsFlatOptions{Prefix: &prefix})
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, b := range page.Segment.BlobItems {
			names = append(names, *b.Name)
		}
	}
	sort.Strings(names)
	out := make([]model.ChatMessage, 0, len(names))
	for _, n := range names {
		resp, err := a.blobs.DownloadStream(ctx, a.container, n, nil)
		if err != nil {
			return nil, err
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		resp.Body.Close()
		if err != nil {
			return nil, err
		}
		var m model.ChatMessage
		if err := json.Unmarshal(data, &m); err != nil {
			return nil, fmt.Errorf("decode %s: %w", n, err)
		}
		out = append(out, m)
	}
	return out, nil
}

// ---- settings ----

func (a *Azure) GetSetting(ctx context.Context, key string) (string, error) {
	e, err := a.get(ctx, tSetting, "setting", key)
	if err != nil {
		return "", err
	}
	return e.Data, nil
}

func (a *Azure) PutSetting(ctx context.Context, key, value string) error {
	return a.upsert(ctx, tSetting, entity{PartitionKey: "setting", RowKey: key, Data: value}, nil)
}

// ---- usage ledger (date-partitioned) ----

func (a *Azure) PutUsage(ctx context.Context, u *model.UsageRecord) error {
	return a.upsert(ctx, tUsage, entity{PartitionKey: DayKey(u.At), RowKey: InvTS(u.At) + "_" + u.ID, Title: u.Kind}, u)
}

func (a *Azure) ListUsage(ctx context.Context, since time.Time) ([]model.UsageRecord, error) {
	return queryAll[model.UsageRecord](ctx, a, tUsage, "PartitionKey ge "+odataQuote(DayKey(since)), 0)
}

// ---- reports (RowKey = report id, so regenerating a period overwrites it) ----

func (a *Azure) PutReport(ctx context.Context, r *model.Report) error {
	return a.upsert(ctx, tReports, entity{PartitionKey: "report", RowKey: r.ID, Title: r.Title}, r)
}

func (a *Azure) GetReport(ctx context.Context, id string) (*model.Report, error) {
	e, err := a.get(ctx, tReports, "report", id)
	if err != nil {
		return nil, err
	}
	return decode[model.Report](e)
}

func (a *Azure) ListReports(ctx context.Context, limit int) ([]model.Report, error) {
	out, err := queryAll[model.Report](ctx, a, tReports, "PartitionKey eq 'report'", 0)
	sort.Slice(out, func(i, j int) bool { return out[i].PeriodEnd.After(out[j].PeriodEnd) })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, err
}
