// Package server exposes the store over HTTP: REST endpoints, an SSE stream
// and the embedded web UI.
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/ASHUTOSH-SWAIN-GIT/sysprof/internal/report"
	"github.com/ASHUTOSH-SWAIN-GIT/sysprof/internal/scheduler"
	"github.com/ASHUTOSH-SWAIN-GIT/sysprof/internal/shield"
	"github.com/ASHUTOSH-SWAIN-GIT/sysprof/internal/sockbypass"
	"github.com/ASHUTOSH-SWAIN-GIT/sysprof/internal/store"
	"github.com/ASHUTOSH-SWAIN-GIT/sysprof/web"
)

// Active groups the subsystems that change kernel behaviour.
type Active struct {
	Shield shield.Shield
	Bypass sockbypass.Bypass
	Sched  scheduler.Scheduler
	// Loopback is true when the server listens on a loopback address only.
	Loopback bool
	// AllowRemote permits state changing requests when the server is not
	// bound to loopback. Off by default: the daemon runs as root.
	AllowRemote bool
}

// New builds the HTTP handler. act may be nil for a read only profiler.
func New(st *store.Store, act *Active) http.Handler {
	mux := http.NewServeMux()
	if act != nil {
		registerActive(mux, act)
	}

	mux.HandleFunc("GET /api/snapshot", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, st.Latest())
	})
	mux.HandleFunc("GET /api/history", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, st.History())
	})
	mux.HandleFunc("GET /api/processes", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, st.Latest().Processes)
	})
	mux.HandleFunc("GET /api/export.csv", func(w http.ResponseWriter, r *http.Request) {
		kind := r.URL.Query().Get("what")
		if kind == "" {
			kind = "syscalls"
		}
		if !slices.Contains(report.Kinds, kind) {
			http.Error(w, "what must be one of syscalls, processes or categories", http.StatusBadRequest)
			return
		}
		var buf bytes.Buffer
		if err := report.Write(&buf, st.Latest(), kind); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="sysprof-%s.csv"`, kind))
		w.Write(buf.Bytes())
	})
	mux.HandleFunc("GET /stream", func(w http.ResponseWriter, r *http.Request) {
		stream(st, act, w, r)
	})

	mux.Handle("/", http.FileServer(http.FS(web.FS)))
	return mux
}

// stream pushes the latest snapshot and the history after every store update.
func stream(st *store.Store, act *Active, w http.ResponseWriter, r *http.Request) {
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
			Active   any `json:"active,omitempty"`
		}{st.Latest(), st.History(), act.states()}
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
