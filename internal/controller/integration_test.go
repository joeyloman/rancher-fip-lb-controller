package controller

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/joeyloman/rancher-fip-lb-controller/pkg/metallb"
	"github.com/stretchr/testify/assert"
	"go.universe.tf/metallb/api/v1beta1"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

func TestController_Integration(t *testing.T) {
	testEnv := &envtest.Environment{
		CRDDirectoryPaths: []string{filepath.Join("..", "..", "config", "crd", "bases")},
	}

	cfg, err := testEnv.Start()
	assert.NoError(t, err)
	defer testEnv.Stop()

	err = v1beta1.AddToScheme(scheme.Scheme)
	assert.NoError(t, err)

	k8sClient, err := client.New(cfg, client.Options{Scheme: scheme.Scheme})
	assert.NoError(t, err)
	assert.NotNil(t, k8sClient)

	clientset, err := kubernetes.NewForConfig(cfg)
	assert.NoError(t, err)

	metallbClient, err := metallb.NewClient(cfg)
	assert.NoError(t, err)

	controller := New(clientset, metallbClient, "rancher-fip-manager", nil)

	// In the integration test, we still want to mock the IPAM client
	mockIPAM := &MockIPAMClient{
		RequestFIPFunc: func(clientSecret, cluster, project, floatingIPPool, serviceNamespace, serviceName, ipaddr string) (string, error) {
			return "1.2.3.4", nil
		},
		ReleaseFIPFunc: func(clientSecret, cluster, project, floatingIPPool, serviceNamespace, serviceName, ipaddr string) error {
			return nil
		},
	}
	controller.reconciler.ipamClient = mockIPAM

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go controller.Run(ctx, 1)

	// Create a namespace
	ns := &v1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "test-ns", Labels: map[string]string{"field.cattle.io/projectId": "p-12345"}}}
	err = k8sClient.Create(context.Background(), ns)
	assert.NoError(t, err)

	// Create rancher-fip-manager namespace
	rancherNS := &v1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "rancher-fip-manager"}}
	err = k8sClient.Create(context.Background(), rancherNS)
	assert.NoError(t, err)

	// Create a secret
	secret := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "rancher-fip-config-p-12345", Namespace: "rancher-fip-manager"},
		Data: map[string][]byte{
			"apiUrl":         []byte("http://localhost:8080"),
			"clientId":       []byte("id"),
			"clientSecret":   []byte("secret"),
			"floatingIPPool": []byte("pool1"),
			"cluster":        []byte("c-12345"),
			"project":        []byte("p-12345"),
		},
	}
	err = k8sClient.Create(context.Background(), secret)
	assert.NoError(t, err)

	// Create a configmap
	cm := &v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "network-interface-mappings", Namespace: "rancher-fip-manager"},
		Data:       map[string]string{"pool1": "eth0"},
	}
	err = k8sClient.Create(context.Background(), cm)
	assert.NoError(t, err)

	// Create a service
	svc := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "test-svc", Namespace: "test-ns"},
		Spec: v1.ServiceSpec{
			Type: v1.ServiceTypeLoadBalancer,
			Ports: []v1.ServicePort{
				{Port: 80, Protocol: v1.ProtocolTCP},
			},
		},
	}
	err = k8sClient.Create(context.Background(), svc)
	assert.NoError(t, err)

	// Wait for the IPAddressPool and L2Advertisement to be created
	assert.Eventually(t, func() bool {
		pool := &v1beta1.IPAddressPool{}
		err := k8sClient.Get(context.Background(), client.ObjectKey{Name: "rancher-fip-test-ns-test-svc", Namespace: "rancher-fip-manager"}, pool)
		return err == nil
	}, 10*time.Second, 1*time.Second)

	assert.Eventually(t, func() bool {
		ad := &v1beta1.L2Advertisement{}
		err := k8sClient.Get(context.Background(), client.ObjectKey{Name: "rancher-fip-test-ns-test-svc", Namespace: "rancher-fip-manager"}, ad)
		return err == nil
	}, 10*time.Second, 1*time.Second)

	// Delete the service
	err = k8sClient.Delete(context.Background(), svc)
	assert.NoError(t, err)

	// Wait for the IPAddressPool and L2Advertisement to be deleted
	assert.Eventually(t, func() bool {
		pool := &v1beta1.IPAddressPool{}
		err := k8sClient.Get(context.Background(), client.ObjectKey{Name: "rancher-fip-test-ns-test-svc", Namespace: "rancher-fip-manager"}, pool)
		return apierrors.IsNotFound(err)
	}, 10*time.Second, 1*time.Second)

	assert.Eventually(t, func() bool {
		ad := &v1beta1.L2Advertisement{}
		err := k8sClient.Get(context.Background(), client.ObjectKey{Name: "rancher-fip-test-ns-test-svc", Namespace: "rancher-fip-manager"}, ad)
		return apierrors.IsNotFound(err)
	}, 10*time.Second, 1*time.Second)
}
