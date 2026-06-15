package client

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"snowden/client/model"
	"time"
)

var httpClient = &http.Client{Timeout: 10 * time.Second}

// fetch performs a cached GET against the NVD endpoint. The raw response body
// is cached by full URL. Sends the NVD_API_KEY header when set (raises the NVD
// rate limit from 5 to 50 requests per 30s).
func fetch(query string) ([]byte, error) {
	nvdUrl := os.Getenv("NVD_URL")
	full := fmt.Sprintf("%s/?%s", nvdUrl, query)

	if body, ok := defaultCache.get(full); ok {
		return body, nil
	}

	req, err := http.NewRequest(http.MethodGet, full, nil)
	if err != nil {
		return nil, NewAPIError(http.StatusBadGateway, "failed to build upstream request")
	}
	if key := os.Getenv("NVD_API_KEY"); key != "" {
		req.Header.Set("apiKey", key)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, NewAPIError(http.StatusBadGateway, "NVD request failed: "+err.Error())
	}

	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, NewAPIError(http.StatusBadGateway, "failed to read NVD response")
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, NewAPIError(http.StatusBadGateway, fmt.Sprintf("NVD returned status %d", resp.StatusCode))
	}

	defaultCache.set(full, body)
	return body, nil
}

func GetVulnerabilityByCweId(cweId string) (model.Vulnerability, error) {
	if cweId == "" {
		return model.Vulnerability{}, NewAPIError(http.StatusBadRequest, "cweId is required")
	}

	body, err := fetch("cweId=" + url.QueryEscape(cweId))
	if err != nil {
		return model.Vulnerability{}, err
	}

	var complete model.CompleteCwe
	if err := json.Unmarshal(body, &complete); err != nil {
		return model.Vulnerability{}, NewAPIError(http.StatusBadGateway, "invalid NVD response")
	}

	vuln, err := model.MarshallCweVulnerability(complete)
	if err != nil {
		return model.Vulnerability{}, NewAPIError(http.StatusNotFound, err.Error())
	}

	return vuln, nil
}

func GetVulnerabilityByCveId(cveId string) ([]model.Vulnerability, error) {
	if cveId == "" {
		return nil, NewAPIError(http.StatusBadRequest, "cveId is required")
	}

	body, err := fetch("cveId=" + url.QueryEscape(cveId))
	if err != nil {
		return nil, err
	}

	var complete model.CompleteCve
	if err := json.Unmarshal(body, &complete); err != nil {
		return nil, NewAPIError(http.StatusBadGateway, "invalid NVD response")
	}

	return model.MarshallCveVulnerability(complete), nil
}
