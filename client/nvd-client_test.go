package client

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func statusOf(t *testing.T, err error) int {
	t.Helper()
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *APIError, got %T: %v", err, err)
	}
	return apiErr.Status
}

func TestGetVulnerabilityByCveId_EmptyId(t *testing.T) {
	_, err := GetVulnerabilityByCveId("")
	if err == nil {
		t.Fatal("expected error for empty cveId")
	}
	if got := statusOf(t, err); got != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", got)
	}
}

func TestGetVulnerabilityByCweId_EmptyId(t *testing.T) {
	_, err := GetVulnerabilityByCweId("")
	if err == nil {
		t.Fatal("expected error for empty cweId")
	}
	if got := statusOf(t, err); got != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", got)
	}
}

func TestGetVulnerabilityByCveId_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("cveId"); got != "CVE-2024-1234" {
			t.Errorf("unexpected cveId query: %s", got)
		}
		_, _ = w.Write([]byte(`{"vulnerabilities":[{"cve":{"id":"CVE-2024-1234"}}]}`))
	}))
	defer srv.Close()
	t.Setenv("NVD_URL", srv.URL)

	got, err := GetVulnerabilityByCveId("CVE-2024-1234")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got[0].Cve.ID != "CVE-2024-1234" {
		t.Fatalf("unexpected result: %+v", got)
	}
}

func TestGetVulnerabilityByCweId_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"vulnerabilities":[{"cve":{"id":"CVE-2024-9999"}}]}`))
	}))
	defer srv.Close()
	t.Setenv("NVD_URL", srv.URL)

	got, err := GetVulnerabilityByCweId("CWE-79")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Cve.ID != "CVE-2024-9999" {
		t.Fatalf("unexpected result: %+v", got)
	}
}

func TestGetVulnerabilityByCweId_EmptyResult(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"vulnerabilities":[]}`))
	}))
	defer srv.Close()
	t.Setenv("NVD_URL", srv.URL)

	_, err := GetVulnerabilityByCweId("CWE-79")
	if err == nil {
		t.Fatal("expected error for empty result, got nil")
	}
	if got := statusOf(t, err); got != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", got)
	}
}

func TestGetVulnerabilityByCveId_BadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`not json`))
	}))
	defer srv.Close()
	t.Setenv("NVD_URL", srv.URL)

	_, err := GetVulnerabilityByCveId("CVE-1")
	if err == nil {
		t.Fatal("expected unmarshal error, got nil")
	}
	if got := statusOf(t, err); got != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d", got)
	}
}

func TestFetch_UpstreamNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	t.Setenv("NVD_URL", srv.URL)

	_, err := GetVulnerabilityByCveId("CVE-500")
	if got := statusOf(t, err); got != http.StatusBadGateway {
		t.Fatalf("expected 502 on upstream 500, got %d", got)
	}
}

func TestFetch_CacheHit(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		_, _ = w.Write([]byte(`{"vulnerabilities":[{"cve":{"id":"CVE-CACHE"}}]}`))
	}))
	defer srv.Close()
	t.Setenv("NVD_URL", srv.URL)

	for i := 0; i < 3; i++ {
		if _, err := GetVulnerabilityByCveId("CVE-CACHE"); err != nil {
			t.Fatalf("call %d failed: %v", i, err)
		}
	}

	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("expected 1 upstream hit (cached after), got %d", got)
	}
}

func TestFetch_SendsApiKeyHeader(t *testing.T) {
	var gotKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("apiKey")
		_, _ = w.Write([]byte(`{"vulnerabilities":[]}`))
	}))
	defer srv.Close()
	t.Setenv("NVD_URL", srv.URL)
	t.Setenv("NVD_API_KEY", "secret-key")

	_, _ = GetVulnerabilityByCveId("CVE-KEY")

	if gotKey != "secret-key" {
		t.Fatalf("expected apiKey header 'secret-key', got %q", gotKey)
	}
}
