package controller

import (
	"context"
	"fmt"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"go.universe.tf/metallb/api/v1beta1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/record"
)

// MockIPAMClient is a mock of the IPAM client
type MockIPAMClient struct {
	RequestFIPFunc func(clientSecret, cluster, project, floatingIPPool, serviceNamespace, serviceName, ipaddr string) (string, error)
	ReleaseFIPFunc func(clientSecret, cluster, project, floatingIPPool, serviceNamespace, serviceName, ipaddr string) error
}

func (m *MockIPAMClient) RequestFIP(clientSecret, cluster, project, floatingIPPool, serviceNamespace, serviceName, ipaddr string) (string, error) {
	return m.RequestFIPFunc(clientSecret, cluster, project, floatingIPPool, serviceNamespace, serviceName, ipaddr)
}

func (m *MockIPAMClient) ReleaseFIP(clientSecret, cluster, project, floatingIPPool, serviceNamespace, serviceName, ipaddr string) error {
	return m.ReleaseFIPFunc(clientSecret, cluster, project, floatingIPPool, serviceNamespace, serviceName, ipaddr)
}

// MockMetalLBClient is a mock of the MetalLB client
type MockMetalLBClient struct {
	CreateIPAddressPoolFunc   func(ctx context.Context, pool *v1beta1.IPAddressPool) error
	CreateL2AdvertisementFunc func(ctx context.Context, ad *v1beta1.L2Advertisement) error
	DeleteIPAddressPoolFunc   func(ctx context.Context, name, namespace string) error
	DeleteL2AdvertisementFunc func(ctx context.Context, name, namespace string) error
	GetIPAddressPoolsFunc     func(ctx context.Context, namespace string) ([]v1beta1.IPAddressPool, error)
}

func (m *MockMetalLBClient) GetIPAddressPools(ctx context.Context, namespace string) ([]v1beta1.IPAddressPool, error) {
	return m.GetIPAddressPoolsFunc(ctx, namespace)
}

func (m *MockMetalLBClient) CreateIPAddressPool(ctx context.Context, pool *v1beta1.IPAddressPool) error {
	return m.CreateIPAddressPoolFunc(ctx, pool)
}

func (m *MockMetalLBClient) CreateL2Advertisement(ctx context.Context, ad *v1beta1.L2Advertisement) error {
	return m.CreateL2AdvertisementFunc(ctx, ad)
}

func (m *MockMetalLBClient) DeleteIPAddressPool(ctx context.Context, name, namespace string) error {
	return m.DeleteIPAddressPoolFunc(ctx, name, namespace)
}

func (m *MockMetalLBClient) DeleteL2Advertisement(ctx context.Context, name, namespace string) error {
	return m.DeleteL2AdvertisementFunc(ctx, name, namespace)
}

func TestController_reconcile(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	logger := logrus.New()
	recorder := record.NewFakeRecorder(10)

	mockIPAM := &MockIPAMClient{
		RequestFIPFunc: func(clientSecret, cluster, project, floatingIPPool, serviceNamespace, serviceName, ipaddr string) (string, error) {
			return "1.2.3.4", nil
		},
	}
	mockMetalLB := &MockMetalLBClient{
		CreateIPAddressPoolFunc: func(ctx context.Context, pool *v1beta1.IPAddressPool) error {
			return nil
		},
		CreateL2AdvertisementFunc: func(ctx context.Context, ad *v1beta1.L2Advertisement) error {
			return nil
		},
	}

	r := &reconciler{
		clientset:     clientset,
		metallbClient: mockMetalLB,
		ipamClient:    mockIPAM,
		logger:        logger,
		recorder:      recorder,
		appNamespace:  "rancher-fip-manager",
		caCertData:    nil,
	}

	// Create a service, namespace, secret, and configmap
	ns := &v1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "test-ns", Labels: map[string]string{"field.cattle.io/projectId": "p-12345"}}}
	_, err := clientset.CoreV1().Namespaces().Create(context.Background(), ns, metav1.CreateOptions{})
	assert.NoError(t, err)

	secret := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "rancher-fip-config-p-12345", Namespace: "rancher-fip-manager"},
		Data: map[string][]byte{
			"apiUrl":         []byte("http://localhost"),
			"clientId":       []byte("id"),
			"clientSecret":   []byte("secret"),
			"floatingIPPool": []byte("pool1"),
			"cluster":        []byte("c-12345"),
			"project":        []byte("p-12345"),
		},
	}
	_, err = clientset.CoreV1().Secrets("rancher-fip-manager").Create(context.Background(), secret, metav1.CreateOptions{})
	assert.NoError(t, err)

	cm := &v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "network-interface-mappings", Namespace: "rancher-fip-manager"},
		Data:       map[string]string{"pool1": "eth0"},
	}
	_, err = clientset.CoreV1().ConfigMaps("rancher-fip-manager").Create(context.Background(), cm, metav1.CreateOptions{})
	assert.NoError(t, err)

	svc := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "test-svc", Namespace: "test-ns"},
		Spec:       v1.ServiceSpec{Type: v1.ServiceTypeLoadBalancer},
	}
	_, err = clientset.CoreV1().Services("test-ns").Create(context.Background(), svc, metav1.CreateOptions{})
	assert.NoError(t, err)

	err = r.reconcile(svc)
	assert.NoError(t, err)

	// Check that the finalizer was added
	updatedSvc, err := clientset.CoreV1().Services("test-ns").Get(context.Background(), "test-svc", metav1.GetOptions{})
	assert.NoError(t, err)
	assert.Contains(t, updatedSvc.ObjectMeta.Finalizers, finalizerName)
}

func TestController_reconcile_delete(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	logger := logrus.New()
	recorder := record.NewFakeRecorder(10)

	ipamReleased := false
	mockIPAM := &MockIPAMClient{
		ReleaseFIPFunc: func(clientSecret, cluster, project, floatingIPPool, serviceNamespace, serviceName, ipaddr string) error {
			ipamReleased = true
			return nil
		},
	}

	poolDeleted := false
	adDeleted := false
	mockMetalLB := &MockMetalLBClient{
		DeleteIPAddressPoolFunc: func(ctx context.Context, name, namespace string) error {
			poolDeleted = true
			return nil
		},
		DeleteL2AdvertisementFunc: func(ctx context.Context, name, namespace string) error {
			adDeleted = true
			return nil
		},
	}

	r := &reconciler{
		clientset:     clientset,
		metallbClient: mockMetalLB,
		ipamClient:    mockIPAM,
		logger:        logger,
		recorder:      recorder,
		appNamespace:  "rancher-fip-manager",
		caCertData:    nil,
	}

	// Create a service, namespace, and secret
	ns := &v1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "test-ns", Labels: map[string]string{"field.cattle.io/projectId": "p-12345"}}}
	_, err := clientset.CoreV1().Namespaces().Create(context.Background(), ns, metav1.CreateOptions{})
	assert.NoError(t, err)

	secret := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "rancher-fip-config-p-12345", Namespace: "rancher-fip-manager"},
		Data: map[string][]byte{
			"apiUrl":         []byte("http://localhost"),
			"clientId":       []byte("id"),
			"clientSecret":   []byte("secret"),
			"floatingIPPool": []byte("pool1"),
			"cluster":        []byte("c-12345"),
			"project":        []byte("p-12345"),
		},
	}
	_, err = clientset.CoreV1().Secrets("rancher-fip-manager").Create(context.Background(), secret, metav1.CreateOptions{})
	assert.NoError(t, err)

	now := metav1.Now()
	svc := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test-svc",
			Namespace:         "test-ns",
			DeletionTimestamp: &now,
			Finalizers:        []string{finalizerName},
			Annotations:       map[string]string{"rancher.k8s.binbash.org/floatingip": "1.2.3.4"},
		},
		Spec: v1.ServiceSpec{Type: v1.ServiceTypeLoadBalancer},
		Status: v1.ServiceStatus{
			LoadBalancer: v1.LoadBalancerStatus{
				Ingress: []v1.LoadBalancerIngress{{IP: "1.2.3.4"}},
			},
		},
	}
	_, err = clientset.CoreV1().Services("test-ns").Create(context.Background(), svc, metav1.CreateOptions{})
	assert.NoError(t, err)

	err = r.reconcile(svc)
	assert.NoError(t, err)

	assert.True(t, ipamReleased, "IPAM FIP should be released")
	assert.True(t, poolDeleted, "IPAddressPool should be deleted")
	assert.True(t, adDeleted, "L2Advertisement should be deleted")

	// Check that the finalizer was removed
	updatedSvc, err := clientset.CoreV1().Services("test-ns").Get(context.Background(), "test-svc", metav1.GetOptions{})
	assert.NoError(t, err)
	assert.NotContains(t, updatedSvc.ObjectMeta.Finalizers, finalizerName)
}

func TestController_reconcile_no_secret(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	logger := logrus.New()
	recorder := record.NewFakeRecorder(10)

	mockIPAM := &MockIPAMClient{}
	mockMetalLB := &MockMetalLBClient{}

	r := &reconciler{
		clientset:     clientset,
		metallbClient: mockMetalLB,
		ipamClient:    mockIPAM,
		logger:        logger,
		recorder:      recorder,
		appNamespace:  "rancher-fip-manager",
		caCertData:    nil,
	}

	// Create a namespace and service, but no secret
	ns := &v1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "test-ns", Labels: map[string]string{"field.cattle.io/projectId": "p-12345"}}}
	_, err := clientset.CoreV1().Namespaces().Create(context.Background(), ns, metav1.CreateOptions{})
	assert.NoError(t, err)

	svc := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "test-svc", Namespace: "test-ns"},
		Spec:       v1.ServiceSpec{Type: v1.ServiceTypeLoadBalancer},
	}
	_, err = clientset.CoreV1().Services("test-ns").Create(context.Background(), svc, metav1.CreateOptions{})
	assert.NoError(t, err)

	err = r.reconcile(svc)
	assert.NoError(t, err, "reconcile should not return an error when secret is not found")

	// Check that finalizer was NOT added
	updatedSvc, err := clientset.CoreV1().Services("test-ns").Get(context.Background(), "test-svc", metav1.GetOptions{})
	assert.NoError(t, err)
	assert.NotContains(t, updatedSvc.ObjectMeta.Finalizers, finalizerName)
}

func TestController_reconcile_ipam_request_error(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	logger := logrus.New()
	recorder := record.NewFakeRecorder(10)

	requestCalled := false
	mockIPAM := &MockIPAMClient{
		RequestFIPFunc: func(clientSecret, cluster, project, floatingIPPool, serviceNamespace, serviceName, ipaddr string) (string, error) {
			requestCalled = true
			return "", assert.AnError
		},
	}
	mockMetalLB := &MockMetalLBClient{}

	r := &reconciler{
		clientset:     clientset,
		metallbClient: mockMetalLB,
		ipamClient:    mockIPAM,
		logger:        logger,
		recorder:      recorder,
		appNamespace:  "rancher-fip-manager",
		caCertData:    nil,
	}

	// Create a service, namespace, secret, and configmap
	ns := &v1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "test-ns", Labels: map[string]string{"field.cattle.io/projectId": "p-12345"}}}
	_, err := clientset.CoreV1().Namespaces().Create(context.Background(), ns, metav1.CreateOptions{})
	assert.NoError(t, err)

	secret := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "rancher-fip-config-p-12345", Namespace: "rancher-fip-manager"},
		Data: map[string][]byte{
			"apiUrl":         []byte("http://localhost"),
			"clientId":       []byte("id"),
			"clientSecret":   []byte("secret"),
			"floatingIPPool": []byte("pool1"),
			"cluster":        []byte("c-12345"),
			"project":        []byte("p-12345"),
		},
	}
	_, err = clientset.CoreV1().Secrets("rancher-fip-manager").Create(context.Background(), secret, metav1.CreateOptions{})
	assert.NoError(t, err)

	cm := &v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "network-interface-mappings", Namespace: "rancher-fip-manager"},
		Data:       map[string]string{"pool1": "eth0"},
	}
	_, err = clientset.CoreV1().ConfigMaps("rancher-fip-manager").Create(context.Background(), cm, metav1.CreateOptions{})
	assert.NoError(t, err)

	svc := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "test-svc", Namespace: "test-ns"},
		Spec:       v1.ServiceSpec{Type: v1.ServiceTypeLoadBalancer},
	}
	_, err = clientset.CoreV1().Services("test-ns").Create(context.Background(), svc, metav1.CreateOptions{})
	assert.NoError(t, err)

	err = r.reconcile(svc)
	assert.Error(t, err, "reconcile should return an error on IPAM request failure")
	assert.True(t, requestCalled, "RequestFIP should have been called")

	// Check that finalizer was NOT added
	updatedSvc, err := clientset.CoreV1().Services("test-ns").Get(context.Background(), "test-svc", metav1.GetOptions{})
	assert.NoError(t, err)
	assert.NotContains(t, updatedSvc.ObjectMeta.Finalizers, finalizerName)
}

func TestController_reconcile_ipam_quota_exceeded(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	logger := logrus.New()
	recorder := record.NewFakeRecorder(10)

	requestCalled := false
	mockIPAM := &MockIPAMClient{
		RequestFIPFunc: func(clientSecret, cluster, project, floatingIPPool, serviceNamespace, serviceName, ipaddr string) (string, error) {
			requestCalled = true
			return "", fmt.Errorf("quota exceeded")
		},
	}
	mockMetalLB := &MockMetalLBClient{}

	r := &reconciler{
		clientset:     clientset,
		metallbClient: mockMetalLB,
		ipamClient:    mockIPAM,
		logger:        logger,
		recorder:      recorder,
		appNamespace:  "rancher-fip-manager",
		caCertData:    nil,
	}

	// Create a service, namespace, secret, and configmap
	ns := &v1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "test-ns", Labels: map[string]string{"field.cattle.io/projectId": "p-12345"}}}
	_, err := clientset.CoreV1().Namespaces().Create(context.Background(), ns, metav1.CreateOptions{})
	assert.NoError(t, err)

	secret := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "rancher-fip-config-p-12345", Namespace: "rancher-fip-manager"},
		Data: map[string][]byte{
			"apiUrl":         []byte("http://localhost"),
			"clientId":       []byte("id"),
			"clientSecret":   []byte("secret"),
			"floatingIPPool": []byte("pool1"),
			"cluster":        []byte("c-12345"),
			"project":        []byte("p-12345"),
		},
	}
	_, err = clientset.CoreV1().Secrets("rancher-fip-manager").Create(context.Background(), secret, metav1.CreateOptions{})
	assert.NoError(t, err)

	cm := &v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "network-interface-mappings", Namespace: "rancher-fip-manager"},
		Data:       map[string]string{"pool1": "eth0"},
	}
	_, err = clientset.CoreV1().ConfigMaps("rancher-fip-manager").Create(context.Background(), cm, metav1.CreateOptions{})
	assert.NoError(t, err)

	svc := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "test-svc", Namespace: "test-ns"},
		Spec:       v1.ServiceSpec{Type: v1.ServiceTypeLoadBalancer},
	}
	_, err = clientset.CoreV1().Services("test-ns").Create(context.Background(), svc, metav1.CreateOptions{})
	assert.NoError(t, err)

	err = r.reconcile(svc)
	assert.NoError(t, err, "reconcile should not return an error on quota exceeded")
	assert.True(t, requestCalled, "RequestFIP should have been called")

	// Check that finalizer was NOT added
	updatedSvc, err := clientset.CoreV1().Services("test-ns").Get(context.Background(), "test-svc", metav1.GetOptions{})
	assert.NoError(t, err)
	assert.NotContains(t, updatedSvc.ObjectMeta.Finalizers, finalizerName)
}

func TestController_reconcile_delete_ipam_release_error(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	logger := logrus.New()
	recorder := record.NewFakeRecorder(10)

	ipamReleased := false
	mockIPAM := &MockIPAMClient{
		ReleaseFIPFunc: func(clientSecret, cluster, project, floatingIPPool, serviceNamespace, serviceName, ipaddr string) error {
			ipamReleased = true
			return assert.AnError
		},
	}

	poolDeleted := false
	adDeleted := false
	mockMetalLB := &MockMetalLBClient{
		DeleteIPAddressPoolFunc: func(ctx context.Context, name, namespace string) error {
			poolDeleted = true
			return nil
		},
		DeleteL2AdvertisementFunc: func(ctx context.Context, name, namespace string) error {
			adDeleted = true
			return nil
		},
	}

	r := &reconciler{
		clientset:     clientset,
		metallbClient: mockMetalLB,
		ipamClient:    mockIPAM,
		logger:        logger,
		recorder:      recorder,
		appNamespace:  "rancher-fip-manager",
		caCertData:    nil,
	}

	// Create a service, namespace, and secret
	ns := &v1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "test-ns", Labels: map[string]string{"field.cattle.io/projectId": "p-12345"}}}
	_, err := clientset.CoreV1().Namespaces().Create(context.Background(), ns, metav1.CreateOptions{})
	assert.NoError(t, err)

	secret := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "rancher-fip-config-p-12345", Namespace: "rancher-fip-manager"},
		Data: map[string][]byte{
			"apiUrl":         []byte("http://localhost"),
			"clientId":       []byte("id"),
			"clientSecret":   []byte("secret"),
			"floatingIPPool": []byte("pool1"),
			"cluster":        []byte("c-12345"),
			"project":        []byte("p-12345"),
		},
	}
	_, err = clientset.CoreV1().Secrets("rancher-fip-manager").Create(context.Background(), secret, metav1.CreateOptions{})
	assert.NoError(t, err)

	now := metav1.Now()
	svc := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test-svc",
			Namespace:         "test-ns",
			DeletionTimestamp: &now,
			Finalizers:        []string{finalizerName},
			Annotations:       map[string]string{"rancher.k8s.binbash.org/floatingip": "1.2.3.4"},
		},
		Spec: v1.ServiceSpec{Type: v1.ServiceTypeLoadBalancer},
		Status: v1.ServiceStatus{
			LoadBalancer: v1.LoadBalancerStatus{
				Ingress: []v1.LoadBalancerIngress{{IP: "1.2.3.4"}},
			},
		},
	}
	_, err = clientset.CoreV1().Services("test-ns").Create(context.Background(), svc, metav1.CreateOptions{})
	assert.NoError(t, err)

	err = r.reconcile(svc)
	assert.Error(t, err)

	assert.True(t, ipamReleased, "IPAM ReleaseFIP should have been called")
	assert.False(t, poolDeleted, "IPAddressPool should not be deleted")
	assert.False(t, adDeleted, "L2Advertisement should not be deleted")

	// Check that the finalizer was NOT removed
	updatedSvc, err := clientset.CoreV1().Services("test-ns").Get(context.Background(), "test-svc", metav1.GetOptions{})
	assert.NoError(t, err)
	assert.Contains(t, updatedSvc.ObjectMeta.Finalizers, finalizerName)
}

func TestController_reconcile_get_ip_address_pools(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	logger := logrus.New()
	recorder := record.NewFakeRecorder(10)

	// Mock IPAM client that returns a successful FIP request
	mockIPAM := &MockIPAMClient{
		RequestFIPFunc: func(clientSecret, cluster, project, floatingIPPool, serviceNamespace, serviceName, ipaddr string) (string, error) {
			return "1.2.3.4", nil
		},
	}

	// Track calls to GetIPAddressPools
	getPoolsCalled := false
	var getPoolsNamespace string
	createPoolCallCount := 0
	mockMetalLB := &MockMetalLBClient{
		CreateIPAddressPoolFunc: func(ctx context.Context, pool *v1beta1.IPAddressPool) error {
			createPoolCallCount++
			// Simulate CIDR overlap error on first call to trigger GetIPAddressPools call
			if createPoolCallCount == 1 {
				return fmt.Errorf("admission webhook \"ipaddresspoolvalidationwebhook.metallb.io\" denied the request: CIDR \"1.2.3.4/32\" in pool \"rancher-fip-test-ns-test-svc\" overlaps with already defined CIDR \"1.2.3.4/32\"")
			}
			// Return success on retry
			return nil
		},
		GetIPAddressPoolsFunc: func(ctx context.Context, namespace string) ([]v1beta1.IPAddressPool, error) {
			getPoolsCalled = true
			getPoolsNamespace = namespace
			// Return a pool with the overlapping CIDR
			return []v1beta1.IPAddressPool{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "existing-pool",
						Namespace: namespace,
					},
					Spec: v1beta1.IPAddressPoolSpec{
						Addresses: []string{"1.2.3.4/32"},
					},
				},
			}, nil
		},
		DeleteIPAddressPoolFunc: func(ctx context.Context, name, namespace string) error {
			return nil
		},
		DeleteL2AdvertisementFunc: func(ctx context.Context, name, namespace string) error {
			return nil
		},
		CreateL2AdvertisementFunc: func(ctx context.Context, ad *v1beta1.L2Advertisement) error {
			return nil
		},
	}

	r := &reconciler{
		clientset:     clientset,
		metallbClient: mockMetalLB,
		ipamClient:    mockIPAM,
		logger:        logger,
		recorder:      recorder,
		appNamespace:  "rancher-fip-manager",
		caCertData:    nil,
	}

	// Create a service, namespace, secret, and configmap
	ns := &v1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "test-ns", Labels: map[string]string{"field.cattle.io/projectId": "p-12345"}}}
	_, err := clientset.CoreV1().Namespaces().Create(context.Background(), ns, metav1.CreateOptions{})
	assert.NoError(t, err)

	secret := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "rancher-fip-config-p-12345", Namespace: "rancher-fip-manager"},
		Data: map[string][]byte{
			"apiUrl":         []byte("http://localhost"),
			"clientId":       []byte("id"),
			"clientSecret":   []byte("secret"),
			"floatingIPPool": []byte("pool1"),
			"cluster":        []byte("c-12345"),
			"project":        []byte("p-12345"),
		},
	}
	_, err = clientset.CoreV1().Secrets("rancher-fip-manager").Create(context.Background(), secret, metav1.CreateOptions{})
	assert.NoError(t, err)

	cm := &v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "network-interface-mappings", Namespace: "rancher-fip-manager"},
		Data:       map[string]string{"pool1": "eth0"},
	}
	_, err = clientset.CoreV1().ConfigMaps("rancher-fip-manager").Create(context.Background(), cm, metav1.CreateOptions{})
	assert.NoError(t, err)

	svc := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "test-svc", Namespace: "test-ns"},
		Spec:       v1.ServiceSpec{Type: v1.ServiceTypeLoadBalancer},
	}
	_, err = clientset.CoreV1().Services("test-ns").Create(context.Background(), svc, metav1.CreateOptions{})
	assert.NoError(t, err)

	err = r.reconcile(svc)
	assert.NoError(t, err)

	// Verify that GetIPAddressPools was called
	assert.True(t, getPoolsCalled, "GetIPAddressPools should have been called")
	assert.Equal(t, "rancher-fip-manager", getPoolsNamespace, "GetIPAddressPools should be called with correct namespace")
}
