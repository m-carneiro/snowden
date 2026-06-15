package client

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetVulnerabilityByCveId_EmptyId(t *testing.T) {
	if _, err := GetVulnerabilityByCveId(""); err == nil {
		t.Fatal("expected error for empty cveId")
	}
}

func TestGetVulnerabilityByCweId_EmptyId(t *testing.T) {
	if _, err := GetVulnerabilityByCweId(""); err == nil {
		t.Fatal("expected error for empty cweId")
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

	if _, err := GetVulnerabilityByCweId("CWE-79"); err == nil {
		t.Fatal("expected error for empty result, got nil")
	}
}

func TestGetVulnerabilityByCveId_BadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`not json`))
	}))
	defer srv.Close()
	t.Setenv("NVD_URL", srv.URL)

	if _, err := GetVulnerabilityByCveId("CVE-1"); err == nil {
		t.Fatal("expected unmarshal error, got nil")
	}
}
