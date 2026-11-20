package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"

	"cynewsfeed/internal/agent"
	"cynewsfeed/internal/model"
	"cynewsfeed/internal/store"
)

// user returns the Easy Auth principal (or "local" when auth is off).
func user(r *http.Request) (id, name string) {
	id = r.Header.Get("X-MS-CLIENT-PRINCIPAL-ID")
	name = r.Header.Get("X-MS-CLIENT-PRINCIPAL-NAME")
	if id == "" {
		id, name = "local", "local"
	}
	return id, name
}

// chatLocks prevents two concurrent replies in the same chat.
var chatLocks sync.Map

func (s *Server) chatRoutes(r chi.Router) {
	r.Get("/agent", s.agentStatus)
	r.Get("/agent/prompts", s.getPrompts)
	r.Put("/agent/prompts", s.putPrompts)
	r.Get("/chats", s.listChats)
	r.Post("/chats", s.createChat)
	r.Get("/chats/{id}", s.getChat)
	r.Patch("/chats/{id}", s.renameChat)
	r.Delete("/chats/{id}", s.deleteChat)
	r.Post("/chats/{id}/messages", s.postMessage)
}

func (s *Server) agentStatus(w http.ResponseWriter, _ *http.Request) {
	if s.agent == nil {
		writeJSON(w, 200, map[string]any{"enabled": false, "reason": s.agentErr})
		return
	}
	writeJSON(w, 200, map[string]any{"enabled": true, "provider": s.agent.Provider(), "model": s.agent.Model(), "tools": s.agent.Tools()})
}

func (s *Server) getPrompts(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"prompts": agent.Prompts(r.Context(), s.store), "defaults": agent.DefaultPrompts})
}

func (s *Server) putPrompts(w http.ResponseWriter, r *http.Request) {
	var body map[string]string
	if !decodeBody(w, r, &body) {
		return
	}
	clean := map[string]string{}
	for k, v := range body {
		if _, ok := agent.DefaultPrompts[k]; !ok {
			writeErr(w, 400, "unknown prompt key "+k)
			return
		}
		if strings.TrimSpace(v) != "" && strings.TrimSpace(v) != strings.TrimSpace(agent.DefaultPrompts[k]) {
			clean[k] = v
		}
	}
	b, _ := json.Marshal(clean)
	if err := s.store.PutSetting(r.Context(), "prompts", string(b)); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.getPrompts(w, r)
}

func (s *Server) listChats(w http.ResponseWriter, r *http.Request) {
	uid, _ := user(r)
	cs, err := s.store.ListChats(r.Context(), uid)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if cs == nil {
		cs = []model.Chat{}
	}
	writeJSON(w, 200, cs)
}

func newChatID() string {
	b := make([]byte, 3)
	_, _ = rand.Read(b)
	return store.InvTS(time.Now()) + hex.EncodeToString(b)
}

func (s *Server) createChat(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Title string `json:"title"`
	}
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body)
	uid, name := user(r)
	now := time.Now().UTC()
	c := &model.Chat{ID: newChatID(), User: uid, UserName: name, Title: strings.TrimSpace(body.Title), CreatedAt: now, UpdatedAt: now}
	if c.Title == "" {
		c.Title = "New chat"
	}
	if err := s.store.PutChat(r.Context(), c); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 201, c)
}

func (s *Server) getChat(w http.ResponseWriter, r *http.Request) {
	uid, _ := user(r)
	c, err := s.store.GetChat(r.Context(), uid, chi.URLParam(r, "id"))
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	msgs, err := s.store.ListChatMessages(r.Context(), c.ID)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	for i := range msgs {
		msgs[i].Native = nil // provider transcript is internal
	}
	_, busy := chatLocks.Load(c.ID)
	writeJSON(w, 200, map[string]any{"chat": c, "messages": msgs, "busy": busy})
}

func (s *Server) renameChat(w http.ResponseWriter, r *http.Request) {
	uid, _ := user(r)
	c, err := s.store.GetChat(r.Context(), uid, chi.URLParam(r, "id"))
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	var body struct {
		Title string `json:"title"`
	}
	if !decodeBody(w, r, &body) {
		return
	}
	if t := strings.TrimSpace(body.Title); t != "" {
		c.Title = truncateRunes(t, 120)
	}
	if err := s.store.PutChat(r.Context(), c); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, c)
}

func (s *Server) deleteChat(w http.ResponseWriter, r *http.Request) {
	uid, _ := user(r)
	if err := s.store.DeleteChat(r.Context(), uid, chi.URLParam(r, "id")); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	w.WriteHeader(204)
}

// postMessage runs an agent turn and streams progress as Server-Sent Events.
func (s *Server) postMessage(w http.ResponseWriter, r *http.Request) {
	if s.agent == nil {
		writeErr(w, 503, s.agentErr)
		return
	}
	uid, _ := user(r)
	c, err := s.store.GetChat(r.Context(), uid, chi.URLParam(r, "id"))
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	var body struct {
		Text  string `json:"text"`
		Brief *struct {
			Type   string `json:"type"`
			Value  string `json:"value"`
			ItemID string `json:"itemId"`
			Reason string `json:"reason"`
		} `json:"brief"`
	}
	if !decodeBody(w, r, &body) {
		return
	}

	// Build the prompt: free text, or a standard brief for a highlight.
	var cctx *model.ChatContext
	prompt := strings.TrimSpace(body.Text)
	display := prompt
	if body.Brief != nil && strings.TrimSpace(body.Brief.Value) != "" {
		cctx = &model.ChatContext{EntityType: body.Brief.Type, EntityValue: strings.TrimSpace(body.Brief.Value), ItemID: body.Brief.ItemID}
		if cctx.ItemID != "" {
			if it, err := s.store.GetItem(r.Context(), cctx.ItemID, false); err == nil {
				cctx.ItemTitle = it.Title
			}
		}
		if prompt == "" {
			tpl := agent.Prompts(r.Context(), s.store)[agent.PromptKind(cctx.EntityType)]
			prompt = agent.RenderPrompt(tpl, *cctx, body.Brief.Reason)
			display = prompt
		} else {
			// Custom question about a highlighted entity.
			label := cctx.EntityType
			prompt = fmt.Sprintf("Regarding the %s %q", label, cctx.EntityValue)
			if cctx.ItemTitle != "" {
				prompt += fmt.Sprintf(" (seen in story %q, id %s)", cctx.ItemTitle, cctx.ItemID)
			}
			prompt += ": " + display
		}
		if cctx.ItemID != "" && body.Text == "" {
			prompt += fmt.Sprintf("\n\n(Context: I clicked this in the story %q, id %s.)", cctx.ItemTitle, cctx.ItemID)
		}
	}
	if prompt == "" {
		writeErr(w, 400, "text or brief is required")
		return
	}
	if len(prompt) > 8000 {
		writeErr(w, 400, "message too long")
		return
	}
	if _, busy := chatLocks.LoadOrStore(c.ID, true); busy {
		writeErr(w, 409, "this chat is still answering the previous message")
		return
	}

	if c.Messages == 0 || c.Title == "New chat" {
		title := display
		if cctx != nil && body.Text == "" {
			title = "Brief: " + cctx.EntityValue
		}
		c.Title = truncateRunes(strings.Join(strings.Fields(title), " "), 80)
	}

	// SSE setup. The agent runs on a detached context so the answer is
	// completed and saved even if the client disconnects.
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Now().Add(20 * time.Minute))
	w.WriteHeader(200)

	var mu sync.Mutex
	clientGone := false
	send := func(v any) {
		mu.Lock()
		defer mu.Unlock()
		if clientGone {
			return
		}
		b, _ := json.Marshal(v)
		if _, err := fmt.Fprintf(w, "data: %s\n\n", b); err != nil {
			clientGone = true
			return
		}
		_ = rc.Flush()
	}
	send(map[string]any{"type": "start", "chat": c})

	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 15*time.Minute)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		defer cancel()
		defer chatLocks.Delete(c.ID)
		if _, err := s.agent.Reply(ctx, c, prompt, display, cctx, func(e agent.Event) { send(e) }); err != nil {
			send(agent.Event{Type: "error", Error: err.Error()})
		}
	}()

	ping := time.NewTicker(15 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-finished:
			return
		case <-r.Context().Done():
			mu.Lock()
			clientGone = true
			mu.Unlock()
			return // the agent keeps running and saves its answer
		case <-ping.C:
			mu.Lock()
			if !clientGone {
				if _, err := fmt.Fprint(w, ": ping\n\n"); err == nil {
					_ = rc.Flush()
				}
			}
			mu.Unlock()
		}
	}
}

func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
