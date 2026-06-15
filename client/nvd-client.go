package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"snowden/client/model"
	"time"
)

var httpClient = &http.Client{Timeout: 10 * time.Second}

func GetVulnerabilityByCweId(cweId string) (model.Vulnerability, error) {
	if cweId == "" {
		return model.Vulnerability{}, errors.New("cweId is required")
	}

	var vulnerability model.CompleteCwe
	nvdUrl := os.Getenv("NVD_URL")

	resp, err := httpClient.Get(fmt.Sprintf("%s/?cweId=%s", nvdUrl, url.QueryEscape(cweId)))
	if err != nil {
		return model.Vulnerability{}, err
	}

	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return model.Vulnerability{}, err
	}

	err = json.Unmarshal(body, &vulnerability)
	if err != nil {
		return model.Vulnerability{}, err
	}

	return model.MarshallCweVulnerability(vulnerability)
}

func GetVulnerabilityByCveId(cveId string) ([]model.Vulnerability, error) {
	if cveId == "" {
		return []model.Vulnerability{}, errors.New("cveId is required")
	}

	var vulnerability model.CompleteCve
	nvdUrl := os.Getenv("NVD_URL")

	resp, err := httpClient.Get(fmt.Sprintf("%s/?cveId=%s", nvdUrl, url.QueryEscape(cveId)))
	if err != nil {
		return []model.Vulnerability{}, err
	}

	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return []model.Vulnerability{}, err
	}

	err = json.Unmarshal(body, &vulnerability)
	if err != nil {
		return []model.Vulnerability{}, err
	}

	return model.MarshallCveVulnerability(vulnerability), nil
}
