package ipam

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newTestServer(handler http.Handler) (*httptest.Server, *x509.CertPool) {
	ts := httptest.NewTLSServer(handler)

	certpool := x509.NewCertPool()
	certpool.AddCert(ts.Certificate())

	return ts, certpool
}

func TestNewClient(t *testing.T) {
	ts, _ := newTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "{\"token\":\"test_token\"}")
	}))
	defer ts.Close()

	// Test with a valid API URL
	client, err := NewClient(ts.URL, "test_client", nil)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if client == nil {
		t.Error("expected a client, got nil")
	}

	// Test with an empty API URL
	_, err = NewClient("", "test_client", nil)
	if err == nil {
		t.Error("expected an error for empty API URL, got nil")
	}
}

func TestRequestFIP(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/auth/token":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintln(w, `{"token":"test_token"}`)
		case "/fip/request":
			w.Header().Set("Content-Type", "application/json")
			var reqBody map[string]string
			if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			respBody := map[string]string{
				"clientSecret":     reqBody["clientSecret"],
				"status":           "approved",
				"cluster":          reqBody["cluster"],
				"project":          reqBody["project"],
				"floatingippool":   reqBody["floatingippool"],
				"servicenamespace": reqBody["servicenamespace"],
				"servicename":      reqBody["servicename"],
				"ipaddr":           "1.2.3.4",
			}
			json.NewEncoder(w).Encode(respBody)
		default:
			http.NotFound(w, r)
		}
	})

	ts, certpool := newTestServer(handler)
	defer ts.Close()

	_, err := x509.ParseCertificate(ts.TLS.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}
	caCertPEM := x509.MarshalPKCS1PrivateKey(ts.TLS.Certificates[0].PrivateKey.(*rsa.PrivateKey))

	client, err := NewClient(ts.URL, "test_client", caCertPEM)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	client.httpClient.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: certpool,
		},
	}

	ip, err := client.RequestFIP("secret", "cluster", "project", "pool", "ns", "service", "")
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if ip != "1.2.3.4" {
		t.Errorf("expected ip 1.2.3.4, got %s", ip)
	}
}

func TestRequestFIPFailures(t *testing.T) {
	// Test case 1: Token endpoint fails
	handler1 := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth/token" {
			http.Error(w, "token error", http.StatusInternalServerError)
		}
	})
	ts1, _ := newTestServer(handler1)
	client1, _ := NewClient(ts1.URL, "test_client", nil)
	client1.httpClient.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	_, err := client1.RequestFIP("secret", "cluster", "project", "pool", "ns", "service", "")
	if err == nil {
		t.Error("expected an error for token failure, got nil")
	}
	ts1.Close()

	// Test case 2: Request FIP endpoint returns non-200
	handler2 := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth/token" {
			fmt.Fprintln(w, `{"token":"test_token"}`)
		} else if r.URL.Path == "/fip/request" {
			http.Error(w, "quota exceeded", http.StatusForbidden)
		}
	})
	ts2, _ := newTestServer(handler2)
	client2, _ := NewClient(ts2.URL, "test_client", nil)
	client2.httpClient.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	_, err = client2.RequestFIP("secret", "cluster", "project", "pool", "ns", "service", "")
	if err == nil {
		t.Error("expected an error for non-200 response, got nil")
	}
	ts2.Close()

	// Test case 3: Malformed JSON response
	handler3 := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth/token" {
			fmt.Fprintln(w, `{"token":"test_token"}`)
		} else if r.URL.Path == "/fip/request" {
			fmt.Fprintln(w, `{"ipaddr":malformed}`)
		}
	})
	ts3, _ := newTestServer(handler3)
	client3, _ := NewClient(ts3.URL, "test_client", nil)
	client3.httpClient.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	_, err = client3.RequestFIP("secret", "cluster", "project", "pool", "ns", "service", "")
	if err == nil {
		t.Error("expected an error for malformed JSON, got nil")
	}
	ts3.Close()

	// Test case 4: Field mismatch
	handler4 := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth/token" {
			fmt.Fprintln(w, `{"token":"test_token"}`)
		} else if r.URL.Path == "/fip/request" {
			w.Header().Set("Content-Type", "application/json")
			var reqBody map[string]string
			json.NewDecoder(r.Body).Decode(&reqBody)
			respBody := map[string]string{
				"clientSecret":     "wrong-secret",
				"status":           "approved",
				"cluster":          reqBody["cluster"],
				"project":          reqBody["project"],
				"floatingippool":   reqBody["floatingippool"],
				"servicenamespace": reqBody["servicenamespace"],
				"servicename":      reqBody["servicename"],
				"ipaddr":           "1.2.3.4",
			}
			json.NewEncoder(w).Encode(respBody)
		}
	})
	ts4, _ := newTestServer(handler4)
	client4, _ := NewClient(ts4.URL, "test_client", nil)
	client4.httpClient.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	_, err = client4.RequestFIP("secret", "cluster", "project", "pool", "ns", "service", "")
	if err == nil {
		t.Error("expected an error for field mismatch, got nil")
	}
	ts4.Close()
}

func TestReleaseFIP(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/auth/token":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintln(w, `{"token":"test_token"}`)
		case "/fip/release":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintln(w, `{"status":"released"}`)
		default:
			http.NotFound(w, r)
		}
	})

	ts, _ := newTestServer(handler)
	defer ts.Close()

	client, _ := NewClient(ts.URL, "test_client", nil)
	client.httpClient.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	err := client.ReleaseFIP("secret", "cluster", "project", "pool", "ns", "service", "1.2.3.4")
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestReleaseFIPFailures(t *testing.T) {
	// Test case 1: Token endpoint fails
	handler1 := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth/token" {
			http.Error(w, "token error", http.StatusInternalServerError)
		}
	})
	ts1, _ := newTestServer(handler1)
	client1, _ := NewClient(ts1.URL, "test_client", nil)
	client1.httpClient.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	err := client1.ReleaseFIP("secret", "cluster", "project", "pool", "ns", "service", "1.2.3.4")
	if err == nil {
		t.Error("expected an error for token failure, got nil")
	}
	ts1.Close()

	// Test case 2: Release FIP endpoint returns non-200
	handler2 := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth/token" {
			fmt.Fprintln(w, `{"token":"test_token"}`)
		} else if r.URL.Path == "/fip/release" {
			http.Error(w, "error", http.StatusInternalServerError)
		}
	})
	ts2, _ := newTestServer(handler2)
	client2, _ := NewClient(ts2.URL, "test_client", nil)
	client2.httpClient.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	err = client2.ReleaseFIP("secret", "cluster", "project", "pool", "ns", "service", "1.2.3.4")
	if err == nil {
		t.Error("expected an error for non-200 response, got nil")
	}
	ts2.Close()

	// Test case 3: Status not "released"
	handler3 := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth/token" {
			fmt.Fprintln(w, `{"token":"test_token"}`)
		} else if r.URL.Path == "/fip/release" {
			fmt.Fprintln(w, `{"status":"failed"}`)
		}
	})
	ts3, _ := newTestServer(handler3)
	client3, _ := NewClient(ts3.URL, "test_client", nil)
	client3.httpClient.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	err = client3.ReleaseFIP("secret", "cluster", "project", "pool", "ns", "service", "1.2.3.4")
	if err == nil {
		t.Error("expected an error for status not released, got nil")
	}
	ts3.Close()
}

func TestListFIPs(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/auth/token":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintln(w, `{"token":"test_token"}`)
		case "/fip/list":
			w.Header().Set("Content-Type", "application/json")
			resp := FIPListResponse{
				ClientSecret: "secret",
				Cluster:      "cluster",
				Project:      "project",
				FloatingIPs: []FloatingIP{
					{
						Project:          "project",
						Cluster:          "cluster",
						FloatingIPPool:   "pool",
						ServiceNamespace: "ns",
						ServiceName:      "service",
						IPAddress:        "1.2.3.4",
					},
				},
			}
			json.NewEncoder(w).Encode(resp)
		default:
			http.NotFound(w, r)
		}
	})

	ts, _ := newTestServer(handler)
	defer ts.Close()

	client, _ := NewClient(ts.URL, "test_client", nil)
	client.httpClient.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	fipList, err := client.ListFIPs("secret", "cluster", "project", "pool")
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if len(fipList.FloatingIPs) != 1 {
		t.Errorf("expected 1 floating IP, got %d", len(fipList.FloatingIPs))
	}
	if fipList.FloatingIPs[0].IPAddress != "1.2.3.4" {
		t.Errorf("expected IP 1.2.3.4, got %s", fipList.FloatingIPs[0].IPAddress)
	}
}

func TestListFIPsFailures(t *testing.T) {
	// Test case 1: Token endpoint fails
	handler1 := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth/token" {
			http.Error(w, "token error", http.StatusInternalServerError)
		}
	})
	ts1, _ := newTestServer(handler1)
	client1, _ := NewClient(ts1.URL, "test_client", nil)
	client1.httpClient.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	_, err := client1.ListFIPs("secret", "cluster", "project", "pool")
	if err == nil {
		t.Error("expected an error for token failure, got nil")
	}
	ts1.Close()

	// Test case 2: List FIPs endpoint returns non-200
	handler2 := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth/token" {
			fmt.Fprintln(w, `{"token":"test_token"}`)
		} else if r.URL.Path == "/fip/list" {
			http.Error(w, "error", http.StatusInternalServerError)
		}
	})
	ts2, _ := newTestServer(handler2)
	client2, _ := NewClient(ts2.URL, "test_client", nil)
	client2.httpClient.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	_, err = client2.ListFIPs("secret", "cluster", "project", "pool")
	if err == nil {
		t.Error("expected an error for non-200 response, got nil")
	}
	ts2.Close()

	// Test case 3: Malformed JSON response
	handler3 := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth/token" {
			fmt.Fprintln(w, `{"token":"test_token"}`)
		} else if r.URL.Path == "/fip/list" {
			fmt.Fprintln(w, `{"floatingips":malformed}`)
		}
	})
	ts3, _ := newTestServer(handler3)
	client3, _ := NewClient(ts3.URL, "test_client", nil)
	client3.httpClient.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	_, err = client3.ListFIPs("secret", "cluster", "project", "pool")
	if err == nil {
		t.Error("expected an error for malformed JSON, got nil")
	}
	ts3.Close()
}

func TestDeleteFIP(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/auth/token":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintln(w, `{"token":"test_token"}`)
		case "/fip/delete":
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	})

	ts, _ := newTestServer(handler)
	defer ts.Close()

	client, _ := NewClient(ts.URL, "test_client", nil)
	client.httpClient.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	err := client.DeleteFIP("secret", "project", "1.2.3.4")
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestDeleteFIPFailures(t *testing.T) {
	// Test case 1: Token endpoint fails
	handler1 := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth/token" {
			http.Error(w, "token error", http.StatusInternalServerError)
		}
	})
	ts1, _ := newTestServer(handler1)
	client1, _ := NewClient(ts1.URL, "test_client", nil)
	client1.httpClient.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	err := client1.DeleteFIP("secret", "project", "1.2.3.4")
	if err == nil {
		t.Error("expected an error for token failure, got nil")
	}
	ts1.Close()

	// Test case 2: Delete FIP endpoint returns non-200
	handler2 := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth/token" {
			fmt.Fprintln(w, `{"token":"test_token"}`)
		} else if r.URL.Path == "/fip/delete" {
			http.Error(w, "error", http.StatusInternalServerError)
		}
	})
	ts2, _ := newTestServer(handler2)
	client2, _ := NewClient(ts2.URL, "test_client", nil)
	client2.httpClient.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	err = client2.DeleteFIP("secret", "project", "1.2.3.4")
	if err == nil {
		t.Error("expected an error for non-200 response, got nil")
	}
	ts2.Close()
}
