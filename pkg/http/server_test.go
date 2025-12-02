package http

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/joeyloman/rancher-fip-lb-controller/pkg/ipam"
	"k8s.io/client-go/kubernetes/fake"
)

func newTestServer(handler http.HandlerFunc) *httptest.Server {
	return httptest.NewServer(handler)
}

func TestHandleFIPList(t *testing.T) {
	mockIpamAPI := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/auth/token":
			w.Write([]byte(`{"token":"test-token"}`))
		case "/fip/list":
			fipList := ipam.FIPListResponse{
				FloatingIPs: []ipam.FloatingIP{
					{Project: "test-project", Cluster: "test-cluster", IPAddress: "1.2.3.4"},
				},
			}
			json.NewEncoder(w).Encode(fipList)
		default:
			http.NotFound(w, r)
		}
	})
	defer mockIpamAPI.Close()

	ipamClient, err := ipam.NewClient(mockIpamAPI.URL, "test-client", nil)
	if err != nil {
		t.Fatal(err)
	}

	clientset := fake.NewSimpleClientset()
	server := NewServer(ipamClient, clientset, "secret", "cluster", "project", []string{"pool1"}, "testuser", "testpassword")

	req, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(server.handleFIPList)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	expected := "<td>test-project</td>"
	if !strings.Contains(rr.Body.String(), expected) {
		t.Errorf("handler returned unexpected body: got %v want body to contain %v",
			rr.Body.String(), expected)
	}
}

func TestHandleRelease(t *testing.T) {
	mockIpamAPI := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/auth/token":
			w.Write([]byte(`{"token":"test-token"}`))
		case "/fip/release":
			w.Write([]byte(`{"status":"released"}`))
		default:
			http.NotFound(w, r)
		}
	})
	defer mockIpamAPI.Close()

	ipamClient, err := ipam.NewClient(mockIpamAPI.URL, "test-client", nil)
	if err != nil {
		t.Fatal(err)
	}

	clientset := fake.NewSimpleClientset()
	server := NewServer(ipamClient, clientset, "secret", "cluster", "project", []string{"pool1"}, "testuser", "testpassword")

	formValues := "project=p&cluster=c&floatingippool=f&servicenamespace=s&servicename=s&ipaddr=1.2.3.4"
	req, err := http.NewRequest("POST", "/release", strings.NewReader(formValues))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(server.handleRelease)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusSeeOther {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusSeeOther)
	}
}

func TestHandleRemove(t *testing.T) {
	mockIpamAPI := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/auth/token":
			w.Write([]byte(`{"token":"test-token"}`))
		case "/fip/delete":
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	})
	defer mockIpamAPI.Close()

	ipamClient, err := ipam.NewClient(mockIpamAPI.URL, "test-client", nil)
	if err != nil {
		t.Fatal(err)
	}

	clientset := fake.NewSimpleClientset()
	server := NewServer(ipamClient, clientset, "secret", "cluster", "project", []string{"pool1"}, "testuser", "testpassword")

	formValues := "project=p&ipaddr=1.2.3.4"
	req, err := http.NewRequest("POST", "/remove", strings.NewReader(formValues))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(server.handleRemove)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusSeeOther {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusSeeOther)
	}
}

func TestHandleFIPList_IPAMError(t *testing.T) {
	mockIpamAPI := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "ipam error", http.StatusInternalServerError)
	})
	defer mockIpamAPI.Close()

	ipamClient, err := ipam.NewClient(mockIpamAPI.URL, "test-client", nil)
	if err != nil {
		t.Fatal(err)
	}

	clientset := fake.NewSimpleClientset()
	server := NewServer(ipamClient, clientset, "secret", "cluster", "project", []string{"pool1"}, "testuser", "testpassword")

	req, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(server.handleFIPList)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusInternalServerError {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusInternalServerError)
	}
}

func TestHandleRelease_FormError(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	server := NewServer(nil, clientset, "secret", "cluster", "project", []string{"pool1"}, "testuser", "testpassword")

	req, err := http.NewRequest("POST", "/release", strings.NewReader("project=p"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(server.handleRelease)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusBadRequest)
	}
}

func TestHandleRemove_FormError(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	server := NewServer(nil, clientset, "secret", "cluster", "project", []string{"pool1"}, "testuser", "testpassword")

	req, err := http.NewRequest("POST", "/remove", strings.NewReader("ipaddr=1.2.3.4"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(server.handleRemove)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusBadRequest)
	}
}
