package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/joeyloman/rancher-fip-lb-controller/internal/controller"
	"github.com/joeyloman/rancher-fip-lb-controller/pkg/http"
	"github.com/joeyloman/rancher-fip-lb-controller/pkg/ipam"
	"github.com/joeyloman/rancher-fip-lb-controller/pkg/metallb"
	"github.com/joeyloman/rancher-fip-lb-controller/pkg/util"
	"github.com/rancher/lasso/pkg/log"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
)

var (
	kubeConfig         string
	kubeContext        string
	appNamespace       string
	leaderElect        bool
	leaseLockName      string
	leaseLockNamespace string
	logLevel           string
	httpServerEnabled  bool
	httpServerPort     int
)

func main() {
	// Initialize logger
	logrus.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})

	flag.StringVar(&kubeConfig, "kubeconfig", os.Getenv("KUBECONFIG"), "Path to a kubeconfig file.")
	flag.StringVar(&kubeContext, "kubecontext", os.Getenv("KUBECONTEXT"), "The name of the kubeconfig context to use.")
	flag.StringVar(&appNamespace, "app-namespace", "rancher-fip-manager", "The namespace of the application.")
	flag.BoolVar(&leaderElect, "leader-elect", true, "Enable leader election for controller.")
	flag.StringVar(&leaseLockName, "lease-lock-name", "rancher-fip-lb-controller-lock", "The name of the leader election lock.")
	flag.StringVar(&leaseLockNamespace, "lease-lock-namespace", "rancher-fip-manager", "The namespace of the leader election lock.")
	flag.StringVar(&logLevel, "log-level", "info", "The level of logging (e.g. debug, info, warn, error).")
	flag.BoolVar(&httpServerEnabled, "enable-http-server", true, "Enable the HTTP server for FIP management.")
	flag.IntVar(&httpServerPort, "http-server-port", 8080, "The port of the HTTP server listening for FIP management requests.")
	flag.Parse()

	level, err := logrus.ParseLevel(logLevel)
	if err != nil {
		logrus.Fatalf("Failed to parse log level: %v", err)
	}
	logrus.SetLevel(level)

	// Create root context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Set up signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		logrus.Info("Shutting down...")
		cancel()
	}()

	// Set up Kubernetes client
	var config *rest.Config
	var configErr error
	if kubeConfig != "" {
		logrus.Infof("Using kubeconfig file: %s", kubeConfig)
		config, configErr = clientcmd.BuildConfigFromFlags("", kubeConfig)
	} else {
		logrus.Info("Using in-cluster config")
		config, configErr = rest.InClusterConfig()
	}
	if configErr != nil {
		logrus.Fatalf("Failed to create Kubernetes config: %v", configErr)
	}

	clientset, clientsetErr := kubernetes.NewForConfig(config)
	if clientsetErr != nil {
		logrus.Fatalf("Failed to create Kubernetes clientset: %v", clientsetErr)
	}

	// Read the CA certificate from the secret
	var caCertData []byte
	caCert, err := clientset.CoreV1().Secrets(appNamespace).Get(ctx, "cacerts", metav1.GetOptions{})
	if err != nil {
		if !errors.IsNotFound(err) {
			logrus.Fatalf("Failed to get cacerts secret: %v", err)
		}
		logrus.Infof("cacerts secret not found, continuing without custom CA")
	} else {
		caCertData = caCert.Data["ca.crt"]
	}

	metallbClient, metallbErr := metallb.NewClient(config)
	if metallbErr != nil {
		logrus.Fatalf("Failed to create MetalLB client: %v", metallbErr)
	}

	if !leaderElect {
		run(ctx, clientset, metallbClient, appNamespace, caCertData, httpServerPort)
		logrus.Info("Controller finished")
		return
	}

	// Leader-election logic
	id := uuid.New().String()
	lock := &resourcelock.LeaseLock{
		LeaseMeta: metav1.ObjectMeta{
			Name:      leaseLockName,
			Namespace: leaseLockNamespace,
		},
		Client: clientset.CoordinationV1(),
		LockConfig: resourcelock.ResourceLockConfig{
			Identity: id,
		},
	}

	leaderelection.RunOrDie(ctx, leaderelection.LeaderElectionConfig{
		Lock:            lock,
		ReleaseOnCancel: true,
		LeaseDuration:   15 * time.Second,
		RenewDeadline:   10 * time.Second,
		RetryPeriod:     2 * time.Second,
		Callbacks: leaderelection.LeaderCallbacks{
			OnStartedLeading: func(ctx context.Context) {
				run(ctx, clientset, metallbClient, appNamespace, caCertData, httpServerPort)
			},
			OnStoppedLeading: func() {
				logrus.Infof("leader lost: %s", id)
				os.Exit(0)
			},
			OnNewLeader: func(identity string) {
				if identity == id {
					// I just became the leader
					return
				}
				logrus.Infof("new leader elected: %s", identity)
			},
		},
	})
}

func run(ctx context.Context, clientset *kubernetes.Clientset, metallbClient *metallb.Client, appNamespace string, caCertData []byte, httpServerPort int) {
	logrus.Info("Starting rancher-fip-lb-controller")

	if httpServerEnabled {
		if err := startHttpServer(ctx, clientset, appNamespace, caCertData, httpServerPort); err != nil {
			log.Errorf("failed to start HTTP server: %s", err)
		}
	}

	c := controller.New(clientset, metallbClient, appNamespace, caCertData)
	c.Run(ctx, 1)
}

func startHttpServer(ctx context.Context, clientset *kubernetes.Clientset, appNamespace string, caCertData []byte, httpServerPort int) error {
	// Only start the HTTP server if the app namespace has a project ID label
	appNs, err := clientset.CoreV1().Namespaces().Get(ctx, appNamespace, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to get app namespace %s: %v", appNamespace, err)
	}

	projectId, ok := appNs.Labels["rancher.k8s.binbash.org/project-name"]
	if !ok {
		return fmt.Errorf("namespace %s does not have a project ID label 'rancher.k8s.binbash.org/project-name'", appNamespace)
	}

	// generate username and password for http basic auth
	httpAuthSecretName := "rancher-fip-http-auth"
	httpAuthSecret, err := clientset.CoreV1().Secrets(appNamespace).Get(ctx, httpAuthSecretName, metav1.GetOptions{})
	if err != nil {
		if errors.IsNotFound(err) {
			log.Infof("HTTP auth secret %s not found, creating it", httpAuthSecretName)

			username, err := util.GenerateRandomString(10)
			if err != nil {
				return fmt.Errorf("failed to generate random string for username: %s", err)
			}
			password, err := util.GenerateRandomString(32)
			if err != nil {
				return fmt.Errorf("failed to generate random string for password: %s", err)
			}

			httpAuthSecret, err = clientset.CoreV1().Secrets(appNamespace).Create(ctx, &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      httpAuthSecretName,
					Namespace: appNamespace,
				},
				StringData: map[string]string{
					"username": username,
					"password": password,
				},
			}, metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("failed to create http auth secret %s: %s", httpAuthSecretName, err)
			}
		} else {
			return fmt.Errorf("failed to get http auth secret %s: %s", httpAuthSecretName, err)
		}
	}

	username := string(httpAuthSecret.Data["username"])
	password := string(httpAuthSecret.Data["password"])

	secretName := fmt.Sprintf("rancher-fip-config-%s", projectId)
	secret, err := clientset.CoreV1().Secrets(appNamespace).Get(ctx, secretName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to get secret %s in namespace %s: %v", secretName, appNamespace, err)
	}

	ipamAPIURL := string(secret.Data["apiUrl"])
	clientSecret := string(secret.Data["clientSecret"])
	cluster := string(secret.Data["cluster"])
	project := string(secret.Data["project"])
	ipamClientID := fmt.Sprintf("client-%s", cluster)

	configMap, err := clientset.CoreV1().ConfigMaps(appNamespace).Get(ctx, "network-interface-mappings", metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to get configmap network-interface-mappings: %w", err)
	}

	var floatingIPPools []string
	for pool := range configMap.Data {
		floatingIPPools = append(floatingIPPools, pool)
	}

	ipamClient, err := ipam.NewClient(ipamAPIURL, ipamClientID, caCertData)
	if err != nil {
		logrus.Fatalf("failed to create ipam client: %s", err)
	}

	httpServer := http.NewServer(ipamClient, clientSecret, cluster, project, floatingIPPools, username, password)
	go httpServer.Start(httpServerPort)

	return nil
}
