package ipam

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

// Client is a client for the external IPAM API.
type Client struct {
	httpClient *http.Client
	apiURL     string
	clientID   string
}

// FIPListResponse defines the structure for the response to a floating IP list request.
type FIPListResponse struct {
	// ClientSecret is an extra secret for authenticating client requests.
	ClientSecret string `json:"clientsecret"`
	// Cluster is the target cluster.
	Cluster string `json:"cluster"`
	// Project is the project for which floating IPs are listed.
	Project string `json:"project"`
	// FloatingIPs is the list of floating IPs.
	FloatingIPs []FloatingIP `json:"floatingips"`
}

// FloatingIP defines the structure for a single floating IP in the list response.
type FloatingIP struct {
	// Project is the project that owns the floating IP.
	Project string `json:"project"`
	// Cluster is the cluster where the floating IP is allocated.
	Cluster string `json:"cluster"`
	// FloatingIPPool is the pool where the floating IP is allocated.
	FloatingIPPool string `json:"floatingippool"`
	// ServiceNamespace is the namespace of the service to expose.
	ServiceNamespace string `json:"servicenamespace"`
	// ServiceName is the name of the service to expose.
	ServiceName string `json:"servicename"`
	// IPAddress is the floating IP address.
	IPAddress string `json:"ipaddr"`
}

// DeleteFIPRequest defines the structure for the request to delete a floating IP.
type DeleteFIPRequest struct {
	ClientSecret string `json:"clientsecret"`
	Project      string `json:"project"`
	IPAddress    string `json:"ipaddr"`
}

// FIPListRequest defines the structure for the fip-list request.
type FIPListRequest struct {
	ClientSecret string `json:"clientsecret"`
}

// NewClient creates a new IPAM client.
func NewClient(apiURL string, clientID string, caCertData []byte) (*Client, error) {
	if apiURL == "" {
		return nil, fmt.Errorf("IPAM API URL is not configured")
	}

	var client *http.Client
	if len(caCertData) > 0 {
		// Create a new HTTP client with the provided CA certificate.
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCertData)
		client = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs: caCertPool,
				},
			},
			Timeout: 10 * time.Second,
		}
	} else {
		// Create a new HTTP client without a custom CA certificate.
		client = &http.Client{
			Timeout: 10 * time.Second,
		}
	}

	return &Client{
		httpClient: client,
		apiURL:     apiURL,
		clientID:   clientID,
	}, nil
}

// getToken gets a JWT from the IPAM API
func (c *Client) getToken() (string, error) {
	reqBody := map[string]string{
		"clientID": c.clientID,
	}
	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("request marshal error: %w", err)
	}

	url := fmt.Sprintf("%s/auth/token", c.apiURL)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonBody))
	if err != nil {
		return "", fmt.Errorf("request error: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("client error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("status code %d", resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("response error: %w", err)
	}

	var tokenResponse struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &tokenResponse); err != nil {
		return "", fmt.Errorf("response unmarshal error: %w", err)
	}

	return tokenResponse.Token, nil
}

// RequestFIP requests a floating IP address from the IPAM API.
func (c *Client) RequestFIP(clientSecret, cluster, project, floatingIPPool, serviceNamespace, serviceName, ipaddr string) (string, error) {
	token, err := c.getToken()
	if err != nil {
		return "", fmt.Errorf("failed to get token for FIP request: %w", err)
	}

	reqBody := map[string]string{
		"clientSecret":     clientSecret,
		"cluster":          cluster,
		"project":          project,
		"floatingippool":   floatingIPPool,
		"servicenamespace": serviceNamespace,
		"servicename":      serviceName,
		"ipaddr":           ipaddr,
	}
	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal FIP request body: %w", err)
	}

	url := fmt.Sprintf("%s/fip/request", c.apiURL)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonBody))
	if err != nil {
		return "", fmt.Errorf("failed to create FIP request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to request FIP: %w", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read FIP response body: %w", err)
	}

	var fipResponse struct {
		ClientSecret     string `json:"clientSecret"`
		Status           string `json:"status"`
		Message          string `json:"message"`
		Cluster          string `json:"cluster"`
		Project          string `json:"project"`
		FloatingIPPool   string `json:"floatingippool"`
		ServiceNamespace string `json:"servicenamespace"`
		ServiceName      string `json:"servicename"`
		IPAddress        string `json:"ipaddr"`
	}
	if err := json.Unmarshal(body, &fipResponse); err != nil {
		return "", fmt.Errorf("failed to unmarshal FIP response: %w", err)
	}

	// check for errors
	if resp.StatusCode != http.StatusOK {
		if strings.Contains(string(body), "quota exceeded") {
			return "", fmt.Errorf("failed to request FIP: quota exceeded")
		}
		return "", fmt.Errorf("failed to request FIP: status code %d (%s)", resp.StatusCode, string(body))
	}

	// do some validation checks
	if fipResponse.ClientSecret != clientSecret {
		return "", fmt.Errorf("failed to request FIP: client secret mismatch")
	}
	if fipResponse.Status != "approved" {
		return "", fmt.Errorf("failed to request FIP: status %s", fipResponse.Status)
	}
	if fipResponse.Cluster != cluster {
		return "", fmt.Errorf("failed to request FIP: cluster mismatch")
	}
	if fipResponse.Project != project {
		return "", fmt.Errorf("failed to request FIP: project mismatch")
	}
	if fipResponse.FloatingIPPool != floatingIPPool {
		return "", fmt.Errorf("failed to request FIP: floating IP pool mismatch")
	}
	if fipResponse.ServiceNamespace != serviceNamespace {
		return "", fmt.Errorf("failed to request FIP: service namespace mismatch")
	}
	if fipResponse.ServiceName != serviceName {
		return "", fmt.Errorf("failed to request FIP: service name mismatch")
	}
	if fipResponse.IPAddress == "" {
		return "", fmt.Errorf("failed to request FIP: IP address is empty")
	}

	return fipResponse.IPAddress, nil
}

// ReleaseFIP releases a floating IP address via the IPAM API.
func (c *Client) ReleaseFIP(clientSecret, cluster, project, floatingIPPool, serviceNamespace, serviceName, ipaddr string) error {
	token, err := c.getToken()
	if err != nil {
		return fmt.Errorf("failed to get token for FIP release: %w", err)
	}

	reqBody := map[string]string{
		"clientSecret":     clientSecret,
		"cluster":          cluster,
		"project":          project,
		"floatingippool":   floatingIPPool,
		"servicenamespace": serviceNamespace,
		"servicename":      serviceName,
		"ipaddr":           ipaddr,
	}
	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("failed to marshal FIP release request body: %w", err)
	}

	url := fmt.Sprintf("%s/fip/release", c.apiURL)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonBody))
	if err != nil {
		return fmt.Errorf("failed to create FIP release request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to release FIP: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to release FIP: status code %d", resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read FIP release response body: %w", err)
	}

	var fipResponse struct {
		Status  string `json:"status"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &fipResponse); err != nil {
		return fmt.Errorf("failed to unmarshal FIP release response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to release FIP: status code %d", resp.StatusCode)
	}

	if fipResponse.Status != "released" {
		return fmt.Errorf("failed to release FIP: status %s", fipResponse.Status)
	}

	return nil
}

// ListFIPs gets a list of all floating IPs from the IPAM API.
func (c *Client) ListFIPs(clientSecret, cluster, project, floatingIPPool string) (*FIPListResponse, error) {
	token, err := c.getToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get token for FIP list request: %w", err)
	}

	// Get a new IP address from the IPAM API.
	reqBody := map[string]string{
		"clientSecret":   clientSecret,
		"cluster":        cluster,
		"project":        project,
		"floatingippool": floatingIPPool,
	}
	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	url := fmt.Sprintf("%s/fip/list", c.apiURL)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create FIP list request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get FloatingIP list: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get FloatingIP list: status code %d", resp.StatusCode)
	}
	var fipListResponse FIPListResponse
	if err := json.NewDecoder(resp.Body).Decode(&fipListResponse); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	return &fipListResponse, nil
}

// DeleteFIP deletes a floating IP from the IPAM API.
// Note: The user requested a DELETE http method, but to be consistent with the other functions
// in this client which send a body, we are using POST here. The endpoint is assumed to be /fip-delete.
func (c *Client) DeleteFIP(clientSecret, project, ipaddr string) error {
	token, err := c.getToken()
	if err != nil {
		return fmt.Errorf("failed to get token for FIP delete request: %w", err)
	}

	reqBody := map[string]string{
		"clientSecret": clientSecret,
		"project":      project,
		"ipaddr":       ipaddr,
	}
	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	url := fmt.Sprintf("%s/fip/delete", c.apiURL)
	req, err := http.NewRequest("DELETE", url, bytes.NewBuffer(jsonBody))
	if err != nil {
		return fmt.Errorf("failed to create FIP delete request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to delete ip address: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to delete ip address: status code %d", resp.StatusCode)
	}
	return nil
}
