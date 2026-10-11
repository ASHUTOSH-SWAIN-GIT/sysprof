package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ASHUTOSH-SWAIN-GIT/sysprof/internal/scheduler"
	"github.com/ASHUTOSH-SWAIN-GIT/sysprof/internal/shield"
	"github.com/ASHUTOSH-SWAIN-GIT/sysprof/internal/sockbypass"
	"github.com/ASHUTOSH-SWAIN-GIT/sysprof/internal/store"
)

func newTestServer(allowRemote bool) http.Handler {
	act := &Active{
		Shield: shield.NewFake(), Bypass: sockbypass.NewFake(), Sched: scheduler.NewFake(),
		AllowRemote: allowRemote, Loopback: true,
	}
	return New(store.New(store.Filter{}, 10), act)
}

func do(h http.Handler, method, path, host string, hdr map[string]string, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "http://"+host+path, strings.NewReader(body))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestGuard(t *testing.T) {
	h := newTestServer(false)
	ok := map[string]string{"X-Sysprof-Action": "1"}

	cases := []struct {
		name string
		host string
		hdr  map[string]string
		want int
	}{
		{"no header", "127.0.0.1:8080", nil, http.StatusForbidden},
		{"cross origin", "127.0.0.1:8080", map[string]string{"X-Sysprof-Action": "1", "Origin": "https://evil.example"}, http.StatusForbidden},
		{"non loopback host", "10.0.0.5:8080", ok, http.StatusForbidden},
		{"same origin", "127.0.0.1:8080", map[string]string{"X-Sysprof-Action": "1", "Origin": "http://127.0.0.1:8080"}, http.StatusOK},
		{"loopback", "localhost:8080", ok, http.StatusOK},
	}
	for _, c := range cases {
		rec := do(h, "POST", "/api/scheduler/stress", c.host, c.hdr, "")
		if rec.Code != c.want {
			t.Errorf("%s: got %d want %d (%s)", c.name, rec.Code, c.want, rec.Body.String())
		}
	}
}

func TestNonLoopbackListenIgnoresHostHeader(t *testing.T) {
	act := &Active{Shield: shield.NewFake(), Bypass: sockbypass.NewFake(), Sched: scheduler.NewFake(), Loopback: false}
	h := New(store.New(store.Filter{}, 10), act)
	// a remote client can claim any Host
	rec := do(h, "POST", "/api/scheduler/stress", "127.0.0.1:8080", map[string]string{"X-Sysprof-Action": "1"}, "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("got %d, want 403", rec.Code)
	}
}

func TestAllowRemote(t *testing.T) {
	h := newTestServer(true)
	rec := do(h, "POST", "/api/scheduler/stress", "10.0.0.5:8080", map[string]string{"X-Sysprof-Action": "1"}, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d", rec.Code)
	}
}

func TestRuleValidationReturns400(t *testing.T) {
	h := newTestServer(false)
	rec := do(h, "POST", "/api/shield/rules", "127.0.0.1:8080",
		map[string]string{"X-Sysprof-Action": "1"}, `{"kind":"open","action":"EPERM","path":"/"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got %d", rec.Code)
	}
}

func TestReadEndpointsNeedNoHeader(t *testing.T) {
	h := newTestServer(false)
	for _, p := range []string{"/api/shield", "/api/bypass", "/api/scheduler"} {
		if rec := do(h, "GET", p, "127.0.0.1:8080", nil, ""); rec.Code != http.StatusOK {
			t.Errorf("%s: %d", p, rec.Code)
		}
	}
}
