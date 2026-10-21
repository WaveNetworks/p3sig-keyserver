package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

// A 502 from the host's burst throttle is retried once with the same body;
// a second gateway error is returned, not looped on.
func TestPostFormRetriesGatewayErrorOnce(t *testing.T) {
	old := gatewayRetryDelay
	gatewayRetryDelay = time.Millisecond
	defer func() { gatewayRetryDelay = old }()

	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.FormValue("action") != "ping" {
			t.Errorf("attempt %d lost the form body", calls)
		}
		if calls == 1 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.Write([]byte(`{"results":{"ok":"yes"}}`))
	}))
	defer srv.Close()

	var out struct{ Ok string }
	if err := postForm(srv.URL, url.Values{"action": {"ping"}}, &out); err != nil {
		t.Fatalf("postForm: %v", err)
	}
	if calls != 2 || out.Ok != "yes" {
		t.Fatalf("calls=%d ok=%q, want 2 calls and the retried result", calls, out.Ok)
	}

	calls = 0
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusBadGateway)
	})
	if err := postForm(srv.URL, url.Values{"action": {"ping"}}, nil); err == nil || calls != 2 {
		t.Fatalf("err=%v calls=%d, want an error after exactly 2 calls", err, calls)
	}
}
