// Package server exposes the store over HTTP: REST endpoints, an SSE stream
// and the embedded web UI.
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/ASHUTOSH-SWAIN-GIT/sysprof/internal/store"
	"github.com/ASHUTOSH-SWAIN-GIT/sysprof/web"
)

// New builds the HTTP handler for the given store.
func New(st *store.Store) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/snapshot", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, st.Latest())
	})
	mux.HandleFunc("GET /api/history", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, st.History())
	})
	mux.HandleFunc("GET /api/processes", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, st.Latest().Processes)
	})
	mux.HandleFunc("GET /stream", func(w http.ResponseWriter, r *http.Request) {
		stream(st, w, r)
	})

	mux.Handle("/", http.FileServer(http.FS(web.FS)))
	return mux
}

// stream pushes the latest snapshot and the history after every store update.
func stream(st *store.Store, w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")

	updates, cancel := st.Subscribe()
	defer cancel()

	send := func() error {
		payload := struct {
			Snapshot any `json:"snapshot"`
			History  any `json:"history"`
		}{st.Latest(), st.History()}
		b, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "data: %s\n\n", b); err != nil {
			return err
		}
		fl.Flush()
		return nil
	}
	if send() != nil {
		return
	}
	for {
		select {
		case <-r.Context().Done():
			return
		case <-updates:
			if send() != nil {
				return
			}
		}
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

// Serve runs the HTTP server until ctx is cancelled.
func Serve(ctx context.Context, addr string, h http.Handler) error {
	srv := &http.Server{Addr: addr, Handler: h}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		srv.Shutdown(shutdown)
	}()
	err := srv.ListenAndServe()
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}
