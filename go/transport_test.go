//go:build cgo && !stogas_gateway

package stogas

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestTransportRejectsInvalidConfigurationBeforeEvidenceAcquisition(t *testing.T) {
	for _, options := range []TransportOptions{
		{Security: "both"},
		{Environment: "unknown"},
		{BaseURL: "http://api.example"},
		{BaseURL: "https://api.example/v1"},
		{BaseURL: "https://key:secret@api.example"},
	} {
		t.Run(options.Security+options.Environment+options.BaseURL, func(t *testing.T) {
			transport, err := NewTransport(options)
			if transport != nil {
				_ = transport.Close()
				t.Fatal("invalid configuration created a transport")
			}
			if err == nil {
				t.Fatal("invalid configuration was accepted")
			}
		})
	}
}

// STOGAS_LIVE=staging|prod sends an invalid API key through each security mode.
func TestLiveGatewayRejectsAnInvalidKeyThroughEachSecurityMode(t *testing.T) {
	environment := os.Getenv("STOGAS_LIVE")
	if environment == "" {
		t.Skip("set STOGAS_LIVE to staging or prod")
	}
	client := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{}}
	for _, security := range []string{"tls", "e2ee"} {
		t.Run(security, func(t *testing.T) {
			transport, err := NewTransport(TransportOptions{Environment: environment, Security: security})
			if err != nil {
				t.Fatal(err)
			}
			defer transport.Close()
			baseURL, err := transport.BaseURL()
			if err != nil {
				t.Fatal(err)
			}
			if parsed, err := url.Parse(baseURL); err != nil || parsed.Hostname() != "127.0.0.1" {
				t.Fatalf("unexpected local endpoint %q", baseURL)
			}
			request, err := http.NewRequest(http.MethodPost, baseURL+"/chat/completions",
				strings.NewReader(`{"model":"stogas-status-monitor","messages":[{"role":"user","content":"ping"}]}`))
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Authorization", "Bearer stogas-status-monitor-uncredentialed")
			request.Header.Set("Content-Type", "application/json")
			response, err := client.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			var rejection struct {
				Error struct {
					Type string `json:"type"`
				} `json:"error"`
			}
			if err := json.NewDecoder(response.Body).Decode(&rejection); err != nil || response.StatusCode != http.StatusUnauthorized || rejection.Error.Type != "authentication_error" {
				t.Fatalf("gateway did not reject the invalid key: HTTP %d %q %v", response.StatusCode, rejection.Error.Type, err)
			}
			var refreshes sync.WaitGroup
			for range 3 {
				refreshes.Go(func() {
					if _, err := transport.RefreshBundle(); err != nil {
						t.Error(err)
					}
				})
			}
			refreshes.Wait()
			_ = transport.Close()
			_ = transport.Close()
			if _, err := transport.RefreshBundle(); !errors.Is(err, ErrTransportClosed) {
				t.Fatalf("closed transport refresh: %v", err)
			}
		})
	}
}
