package server

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ASHUTOSH-SWAIN-GIT/sysprof/internal/shield"
)

// states is the extra SSE payload. Safe to call on a nil receiver.
func (a *Active) states() any {
	if a == nil {
		return nil
	}
	return map[string]any{
		"shield":    a.Shield.State(),
		"bypass":    a.Bypass.State(),
		"scheduler": a.Sched.State(),
	}
}

// guard protects state changing endpoints. The daemon runs as root and
// listens on localhost, so a web page the user visits must not be able to
// drive it:
//   - a custom header forces a CORS preflight, which we never answer
//   - a cross site Origin is rejected
//   - requests are refused when the listen address is not loopback, unless
//     explicitly allowed (a remote client can fake any Host header, so the
//     listen address is what counts)
//   - the Host header must be loopback, which stops DNS rebinding
func (a *Active) guard(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Sysprof-Action") != "1" {
			http.Error(w, "missing X-Sysprof-Action header", http.StatusForbidden)
			return
		}
		if o := r.Header.Get("Origin"); o != "" && !strings.HasSuffix(o, "//"+r.Host) {
			http.Error(w, "cross origin request refused", http.StatusForbidden)
			return
		}
		if !a.AllowRemote && (!a.Loopback || !isLoopback(r.Host)) {
			http.Error(w, "state changing requests need a loopback listen address (see --unsafe-remote-control)", http.StatusForbidden)
			return
		}
		h(w, r)
	}
}

// IsLoopbackAddr reports whether a listen address binds loopback only.
func IsLoopbackAddr(addr string) bool { return isLoopback(addr) }

func isLoopback(hostport string) bool {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		host = hostport
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

func fail(w http.ResponseWriter, code int, err error) {
	http.Error(w, err.Error(), code)
}

func registerActive(mux *http.ServeMux, a *Active) {
	// --- shield
	mux.HandleFunc("GET /api/shield", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, a.Shield.State())
	})
	mux.HandleFunc("POST /api/shield/rules", a.guard(func(w http.ResponseWriter, r *http.Request) {
		var rule shield.Rule
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&rule); err != nil {
			fail(w, http.StatusBadRequest, err)
			return
		}
		out, err := a.Shield.AddRule(rule)
		if err != nil {
			fail(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, out)
	}))
	mux.HandleFunc("DELETE /api/shield/rules/{id}", a.guard(func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.Atoi(r.PathValue("id"))
		if err != nil {
			fail(w, http.StatusBadRequest, err)
			return
		}
		if err := a.Shield.DeleteRule(id); err != nil {
			fail(w, http.StatusNotFound, err)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	}))
	mux.HandleFunc("POST /api/shield/simulate", a.guard(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()
		res, err := a.Shield.Simulate(ctx)
		if err != nil {
			fail(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, map[string]any{"attempts": res})
	}))

	// --- bypass
	mux.HandleFunc("GET /api/bypass", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, a.Bypass.State())
	})
	mux.HandleFunc("POST /api/bypass/toggle", a.guard(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Enabled bool `json:"enabled"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&body); err != nil {
			fail(w, http.StatusBadRequest, err)
			return
		}
		if err := a.Bypass.SetEnabled(body.Enabled); err != nil {
			fail(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, a.Bypass.State())
	}))
	mux.HandleFunc("POST /api/bypass/benchmark", a.guard(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Rounds int `json:"rounds"`
		}
		json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&body)
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()
		res, err := a.Bypass.Benchmark(ctx, body.Rounds)
		if err != nil {
			fail(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, res)
	}))

	// --- scheduler
	mux.HandleFunc("GET /api/scheduler", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, a.Sched.State())
	})
	mux.HandleFunc("POST /api/scheduler/policy", a.guard(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Policy string `json:"policy"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&body); err != nil {
			fail(w, http.StatusBadRequest, err)
			return
		}
		if err := a.Sched.SetPolicy(body.Policy); err != nil {
			fail(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, a.Sched.State())
	}))
	mux.HandleFunc("POST /api/scheduler/stress", a.guard(func(w http.ResponseWriter, r *http.Request) {
		if err := a.Sched.Stress(); err != nil {
			fail(w, http.StatusConflict, err)
			return
		}
		writeJSON(w, a.Sched.State())
	}))
}
