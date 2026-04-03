package controller

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/joeyloman/rancher-fip-lb-controller/pkg/ipam"
	"github.com/joeyloman/rancher-fip-lb-controller/pkg/metallb"
	"github.com/joeyloman/rancher-fip-lb-controller/pkg/purelb"
	"github.com/sirupsen/logrus"
	"go.universe.tf/metallb/api/v1beta1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"
)

const (
	finalizerName = "rancher.k8s.binbash.org/floatingip-cleanup"
)

// Controller watches for service events and reconciles the state of FIPs.
type Controller struct {
	clientset       kubernetes.Interface
	metallbClient   *metallb.Client
	purelbClient    *purelb.Client
	serviceInformer cache.SharedIndexInformer
	queue           workqueue.RateLimitingInterface
	reconciler      *reconciler
	recorder        record.EventRecorder
}

// New creates a new controller.
func New(clientset kubernetes.Interface, metallbClient *metallb.Client, purelbClient *purelb.Client, appNamespace string, caCertData []byte) *Controller {
	informerFactory := informers.NewSharedInformerFactory(clientset, 0)
	serviceInformer := informerFactory.Core().V1().Services().Informer()

	queue := workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter())

	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartLogging(logrus.Infof)
	eventBroadcaster.StartRecordingToSink(&typedcorev1.EventSinkImpl{Interface: clientset.CoreV1().Events("")})
	recorder := eventBroadcaster.NewRecorder(scheme.Scheme, v1.EventSource{Component: "rancher-fip-lb-controller"})

	c := &Controller{
		clientset:       clientset,
		metallbClient:   metallbClient,
		purelbClient:    purelbClient,
		serviceInformer: serviceInformer,
		queue:           queue,
		recorder:        recorder,
	}
	c.reconciler = &reconciler{
		clientset:     clientset,
		metallbClient: metallbClient,
		purelbClient:  purelbClient,
		recorder:      recorder,
		appNamespace:  appNamespace,
		caCertData:    caCertData,
	}

	serviceInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    c.addFunc,
		UpdateFunc: c.updateFunc,
		DeleteFunc: c.deleteFunc,
	})

	return c
}

// Run starts the controller.
func (c *Controller) Run(ctx context.Context, workers int) {
	defer c.queue.ShutDown()

	go c.serviceInformer.Run(ctx.Done())

	if !cache.WaitForCacheSync(ctx.Done(), c.serviceInformer.HasSynced) {
		return
	}

	for i := 0; i < workers; i++ {
		go wait.Until(c.runWorker, time.Second, ctx.Done())
	}

	<-ctx.Done()
}

func (c *Controller) runWorker() {
	for c.processNextItem() {
	}
}

func (c *Controller) processNextItem() bool {
	key, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(key)

	err := c.reconcile(key.(string))
	if err != nil {
		logrus.Errorf("Error reconciling service: %v", err)
		c.queue.AddRateLimited(key)
	} else {
		c.queue.Forget(key)
	}
	return true
}

type ipamClient interface {
	RequestFIP(clientSecret, cluster, project, floatingIPPool, serviceNamespace, serviceName, ipaddr, floatingIPGroup string) (string, string, string, error)
	ReleaseFIP(clientSecret, cluster, project, floatingIPPool, serviceNamespace, serviceName, ipaddr, floatingIPGroup string) error
}

type metallbClient interface {
	CreateIPAddressPool(ctx context.Context, pool *v1beta1.IPAddressPool) error
	CreateL2Advertisement(ctx context.Context, ad *v1beta1.L2Advertisement) error
	DeleteIPAddressPool(ctx context.Context, name, namespace string) error
	DeleteL2Advertisement(ctx context.Context, name, namespace string) error
	GetIPAddressPools(ctx context.Context, namespace string) ([]v1beta1.IPAddressPool, error)
	GetIPAddressPool(ctx context.Context, name, namespace string) (*v1beta1.IPAddressPool, error)
	UpdateIPAddressPool(ctx context.Context, pool *v1beta1.IPAddressPool) error
}

type purelbClient interface {
	CreateServiceGroup(ctx context.Context, group *purelb.ServiceGroup) error
	CreateLBNodeAgent(ctx context.Context, agent *purelb.LBNodeAgent) error
	DeleteServiceGroup(ctx context.Context, name, namespace string) error
	DeleteLBNodeAgent(ctx context.Context, name, namespace string) error
	GetServiceGroups(ctx context.Context, namespace string) ([]purelb.ServiceGroup, error)
}

// reconciler reconciles a Service object
type reconciler struct {
	clientset     kubernetes.Interface
	metallbClient metallbClient
	purelbClient  purelbClient
	ipamClient    ipamClient
	logger        *logrus.Logger
	recorder      record.EventRecorder
	appNamespace  string
	caCertData    []byte
}

func (c *Controller) reconcile(key string) error {
	_, _, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return fmt.Errorf("invalid resource key: %s", key)
	}

	obj, exists, err := c.serviceInformer.GetIndexer().GetByKey(key)
	if err != nil {
		return err
	}
	if !exists {
		logrus.Debugf("Service '%s' in work queue no longer exists", key)
		return nil
	}

	svc := obj.(*v1.Service).DeepCopy()
	return c.reconciler.reconcile(svc)
}

// getProjectIDFromAppNamespace retrieves the project ID from the controller's application namespace.
func (r *reconciler) getProjectIDFromAppNamespace() (string, error) {
	// Get the the projectId from the "rancher.k8s.binbash.org/project-name" label of namespace r.appNamespace.
	appNs, err := r.clientset.CoreV1().Namespaces().Get(context.Background(), r.appNamespace, metav1.GetOptions{})
	if err != nil {
		if errors.IsNotFound(err) {
			logrus.Debugf("Application namespace %s does not exist, this is not a virtual cluster", r.appNamespace)
			return "", nil
		}
		return "", fmt.Errorf("failed to get namespace %s: %w", r.appNamespace, err)
	}
	projectId, ok := appNs.Labels["rancher.k8s.binbash.org/project-name"]
	if !ok {
		logrus.Debugf("Application namespace %s does not have a project ID label, this is not a virtual cluster", r.appNamespace)
		return "", nil
	}
	return projectId, nil
}

func (r *reconciler) reconcile(svc *v1.Service) error {
	var ipAddress string
	var poolName string
	var floatingIPGroup string
	var projectId string
	var ok bool

	logger := logrus.WithFields(logrus.Fields{
		"service":    fmt.Sprintf("%s/%s", svc.Namespace, svc.Name),
		"serviceUID": svc.UID,
	})

	logger.Info("Reconciling Service")

	if svc.Annotations["rancher.k8s.binbash.org/floatingip-group"] != "" {
		floatingIPGroup = svc.Annotations["rancher.k8s.binbash.org/floatingip-group"]
	}

	// Handle service deletion
	if svc.ObjectMeta.DeletionTimestamp != nil {
		if containsString(svc.ObjectMeta.Finalizers, finalizerName) {
			ns, err := r.clientset.CoreV1().Namespaces().Get(context.Background(), svc.Namespace, metav1.GetOptions{})
			if err != nil {
				return fmt.Errorf("failed to get namespace %s: %w", svc.Namespace, err)
			}

			// Check if the namespace if part of a project, if not check if the cluster is part of a project
			projectId, err = r.getProjectIDFromAppNamespace()
			if err != nil {
				return err
			}
			if projectId == "" {
				projectId, ok = ns.Labels["field.cattle.io/projectId"]
				if !ok {
					logger.Infof("Service namespace %s does not have a project ID label, skipping FloatingIP request", svc.Namespace)

					return nil
				}
			}

			// Create a new IPAM client
			secretName := fmt.Sprintf("rancher-fip-config-%s", projectId)
			secret, err := r.clientset.CoreV1().Secrets(r.appNamespace).Get(context.Background(), secretName, metav1.GetOptions{})
			if err != nil {
				if errors.IsNotFound(err) {
					logger.Warnf("Secret %s not found in namespace %s, skipping FloatingIP request", secretName, r.appNamespace)
					return nil
				}
				return fmt.Errorf("failed to get secret %s: %w", secretName, err)
			}

			clientId := fmt.Sprintf("client-%s", string(secret.Data["cluster"]))

			// Release the floating IP
			if svc.Annotations != nil {
				ipAddress = svc.Annotations["rancher.k8s.binbash.org/floatingip"]
			}
			if ipAddress != "" {
				if r.ipamClient == nil {
					ipamClient, err := ipam.NewClient(
						string(secret.Data["apiUrl"]),
						clientId,
						r.caCertData,
					)
					if err != nil {
						return fmt.Errorf("failed to create IPAM client: %w", err)
					}
					r.ipamClient = ipamClient
				}

				// Determine the floating IP pool name
				staticNetworkName := svc.Annotations["rancher.k8s.binbash.org/static-network"]
				fipPoolName := staticNetworkName
				if fipPoolName == "" {
					fipPoolName = string(secret.Data["floatingIPPool"])
				} else {
					logger.Infof("Found request for static network %s for service %s/%s", fipPoolName, svc.Namespace, svc.Name)
				}

				err = r.ipamClient.ReleaseFIP(
					string(secret.Data["clientSecret"]),
					string(secret.Data["cluster"]),
					string(secret.Data["project"]),
					fipPoolName,
					svc.Namespace,
					svc.Name,
					ipAddress,
					floatingIPGroup,
				)
				if err != nil {
					return fmt.Errorf("failed to release FIP: %w", err)
				}

				// Delete the IP address annotation
				err = wait.PollImmediate(5*time.Second, 60*time.Second, func() (bool, error) {
					currentSvc, err := r.clientset.CoreV1().Services(svc.Namespace).Get(context.Background(), svc.Name, metav1.GetOptions{})
					if err != nil {
						if errors.IsNotFound(err) {
							// Service is gone, so we are done.
							return true, nil
						}
						// Some other error getting the service, we can't proceed.
						return false, err
					}

					// If annotation is already gone, we're done.
					if _, ok := currentSvc.Annotations["rancher.k8s.binbash.org/floatingip"]; !ok {
						return true, nil
					}

					svcToUpdate := currentSvc.DeepCopy()
					delete(svcToUpdate.Annotations, "rancher.k8s.binbash.org/floatingip")

					_, err = r.clientset.CoreV1().Services(svcToUpdate.Namespace).Update(context.Background(), svcToUpdate, metav1.UpdateOptions{})
					if err == nil {
						// Success
						return true, nil
					}

					logger.Warnf("Failed to remove floatingip annotation from service %s/%s, will retry: %v", currentSvc.Namespace, currentSvc.Name, err)
					return false, nil
				})
				if err != nil {
					return fmt.Errorf("failed to remove floatingip annotation from service %s/%s: %w", svc.Namespace, svc.Name, err)
				}

				logger.Infof("Successfully released FIP %s", ipAddress)
			}

			if ipAddress != "" {
				// Check if the floatingIPGroup string is not empty
				skipDeletion := false
				if floatingIPGroup != "" {
					// Check if there are more services with the same floatingIPGroup and ip address
					serviceList, err := r.clientset.CoreV1().Services("").List(context.Background(), metav1.ListOptions{})
					if err != nil {
						return fmt.Errorf("failed to list services: %w", err)
					}
					for _, otherSvc := range serviceList.Items {
						if otherSvc.Name == svc.Name && otherSvc.Namespace == svc.Namespace {
							continue
						}
						otherFloatingIPGroup := otherSvc.Annotations["rancher.k8s.binbash.org/floatingip-group"]
						otherFloatingIP := otherSvc.Annotations["rancher.k8s.binbash.org/floatingip"]
						if otherFloatingIPGroup == floatingIPGroup && otherFloatingIP == ipAddress {
							skipDeletion = true
							break
						}
					}
				}

				if !skipDeletion {
					// Check if the allocatedIPAddress is an IPv4 or IPv6 address so we can set the poolName
					ip := net.ParseIP(ipAddress)
					if ip == nil {
						return fmt.Errorf("failed to parse allocated IP address: %s", ipAddress)
					}
					if ip.To4() != nil {
						poolName = fmt.Sprintf("ip4-%s", ipAddress)
					} else {
						// For IPv6, replace ":" with "." in the address
						ipv6Formatted := strings.ReplaceAll(ipAddress, ":", ".")
						poolName = fmt.Sprintf("ip6-%s", ipv6Formatted)
					}

					if string(secret.Data["loadBalancerType"]) == "metallb" {
						// Delete MetalLB resources
						if err := r.metallbClient.DeleteIPAddressPool(context.Background(), poolName, r.appNamespace); err != nil && !errors.IsNotFound(err) {
							return fmt.Errorf("failed to delete IPAddressPool %s: %w", poolName, err)
						}
						if err := r.metallbClient.DeleteL2Advertisement(context.Background(), poolName, r.appNamespace); err != nil && !errors.IsNotFound(err) {
							return fmt.Errorf("failed to delete L2Advertisement %s: %w", poolName, err)
						}
					} else if string(secret.Data["loadBalancerType"]) == "purelb" {
						// Delete PureLB resources
						if err := r.purelbClient.DeleteServiceGroup(context.Background(), poolName, r.appNamespace); err != nil && !errors.IsNotFound(err) {
							return fmt.Errorf("failed to delete ServiceGroup %s: %w", poolName, err)
						}
						// Not needed for now, but keeping the code here for future reference
						// if err := r.purelbClient.DeleteLBNodeAgent(context.Background(), poolName, r.appNamespace); err != nil && !errors.IsNotFound(err) {
						// 	return fmt.Errorf("failed to delete LBNodeAgent %s: %w", poolName, err)
						// }
					}
				}
			}

			// Remove the finalizer
			err = wait.PollImmediate(5*time.Second, 60*time.Second, func() (bool, error) {
				currentSvc, err := r.clientset.CoreV1().Services(svc.Namespace).Get(context.Background(), svc.Name, metav1.GetOptions{})
				if err != nil {
					if errors.IsNotFound(err) {
						// Service is gone, so we are done.
						return true, nil
					}
					// Some other error getting the service, we can't proceed.
					return false, err
				}

				// If finalizer is already gone, we're done.
				if !containsString(currentSvc.ObjectMeta.Finalizers, finalizerName) {
					return true, nil
				}

				currentSvc.ObjectMeta.Finalizers = removeString(currentSvc.ObjectMeta.Finalizers, finalizerName)
				_, err = r.clientset.CoreV1().Services(currentSvc.Namespace).Update(context.Background(), currentSvc, metav1.UpdateOptions{})
				if err != nil {
					logger.Warnf("Failed to remove finalizer from service %s/%s, will retry: %v", currentSvc.Namespace, currentSvc.Name, err)
					// Return false, nil to continue polling.
					return false, nil
				}

				// Success
				return true, nil
			})

			if err != nil {
				return fmt.Errorf("failed to remove finalizer from service %s/%s: %w", svc.Namespace, svc.Name, err)
			}
		}
		return nil
	}

	// Check if the service already has a load balancer IP
	if len(svc.Status.LoadBalancer.Ingress) > 0 {
		logger.Infof("Service %s/%s already has a load balancer IP, skipping FloatingIP request", svc.Namespace, svc.Name)
		return nil
	}

	ns, err := r.clientset.CoreV1().Namespaces().Get(context.Background(), svc.Namespace, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to get namespace %s: %w", svc.Namespace, err)
	}

	// Check if the namespace if part of a project, if not check if the cluster is part of a project
	projectId, err = r.getProjectIDFromAppNamespace()
	if err != nil {
		return err
	}
	if projectId == "" {
		projectId, ok = ns.Labels["field.cattle.io/projectId"]
		if !ok {
			logger.Infof("Service namespace %s does not have a project ID label, skipping FloatingIP request", svc.Namespace)

			return nil
		}
	}

	logger = logger.WithField("projectID", projectId)
	logger.Infof("Service is in project")

	// Construct the secret name and get the secret
	secretName := fmt.Sprintf("rancher-fip-config-%s", projectId)
	secret, err := r.clientset.CoreV1().Secrets(r.appNamespace).Get(context.Background(), secretName, metav1.GetOptions{})
	if err != nil {
		if errors.IsNotFound(err) {
			logger.Warnf("Secret %s not found in namespace %s, skipping FloatingIP request", secretName, r.appNamespace)
			return nil
		}
		return fmt.Errorf("failed to get secret %s: %w", secretName, err)
	}

	logger.Infof("Successfully fetched secret %s", secret.Name)

	// Generate a client ID
	clientId := fmt.Sprintf("client-%s", string(secret.Data["cluster"]))

	// Get the network-interface-mappings configmap
	configMap, err := r.clientset.CoreV1().ConfigMaps(r.appNamespace).Get(context.Background(), "network-interface-mappings", metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to get configmap network-interface-mappings: %w", err)
	}

	// Look up the network interface
	staticNetworkName := svc.Annotations["rancher.k8s.binbash.org/static-network"]
	fipPoolName := staticNetworkName
	if fipPoolName == "" {
		fipPoolName = string(secret.Data["floatingIPPool"])
	} else {
		logger.Infof("Found request for static network %s for service %s/%s", fipPoolName, svc.Namespace, svc.Name)
	}

	networkInterface, ok := configMap.Data[fipPoolName]
	if !ok {
		return fmt.Errorf("no network interface found for floating ip pool %s", fipPoolName)
	}
	logger.Infof("Found network interface %s for floating ip pool %s", networkInterface, fipPoolName)

	// Check if a static IP is given in the service annotations
	ipAddress = svc.Annotations["rancher.k8s.binbash.org/static-ip"]
	if ipAddress != "" {
		logger.Infof("Found request for static IP %s for service %s/%s", ipAddress, svc.Namespace, svc.Name)
	}

	// Create a new IPAM client
	if r.ipamClient == nil {
		ipamClient, err := ipam.NewClient(
			string(secret.Data["apiUrl"]),
			clientId,
			r.caCertData,
		)
		if err != nil {
			return fmt.Errorf("failed to create IPAM client: %w", err)
		}
		r.ipamClient = ipamClient
	}

	// Request a floating IP
	allocatedIPAddress, subnet, sharedKey, err := r.ipamClient.RequestFIP(
		string(secret.Data["clientSecret"]),
		string(secret.Data["cluster"]),
		string(secret.Data["project"]),
		fipPoolName,
		svc.Namespace,
		svc.Name,
		ipAddress,
		floatingIPGroup,
	)
	if err != nil {
		if strings.Contains(err.Error(), "quota exceeded") {
			logger.Infof("failed to request FIP: quota exceeded for project %s service %s/%s, skipping", string(secret.Data["project"]), svc.Namespace, svc.Name)
			r.recorder.Eventf(svc, v1.EventTypeWarning, "QuotaExceeded", "Failed to request FloatingIP for Service Load Balancer: quota exceeded for project %s", string(secret.Data["project"]))
			return nil
		}
		if strings.Contains(err.Error(), "denied the request") {
			logger.Errorf("%s", err)
			r.recorder.Eventf(svc, v1.EventTypeWarning, "RequestDenied", "Failed to request FloatingIP for Service Load Balancer: request denied for project %s", string(secret.Data["project"]))
			return nil
		}
		return fmt.Errorf("failed to request FIP: %w", err)
	}
	logger.Infof("Successfully requested FIP %s", allocatedIPAddress)

	// Check if the allocatedIPAddress is an IPv4 or IPv6 address so we can set the poolName
	ip := net.ParseIP(allocatedIPAddress)
	if ip == nil {
		return fmt.Errorf("failed to parse allocated IP address: %s", allocatedIPAddress)
	}
	if ip.To4() != nil {
		poolName = fmt.Sprintf("ip4-%s", allocatedIPAddress)
	} else {
		// For IPv6, replace ":" with "." in the address
		ipv6Formatted := strings.ReplaceAll(allocatedIPAddress, ":", ".")
		poolName = fmt.Sprintf("ip6-%s", ipv6Formatted)
	}

	if string(secret.Data["loadBalancerType"]) == "metallb" {
		// Check if floatingIPGroup is not empty and if the IPAddressPool already exists
		poolAlreadyExists := false
		if floatingIPGroup != "" {
			existingPool, err := r.metallbClient.GetIPAddressPool(context.Background(), poolName, r.appNamespace)
			if err == nil && existingPool != nil {
				// Pool exists, update it by adding the namespace if not already present
				logger.Infof("IPAddressPool %s already exists, updating with namespace %s", poolName, svc.Namespace)
				namespaceExists := false
				for _, ns := range existingPool.Spec.AllocateTo.Namespaces {
					if ns == svc.Namespace {
						namespaceExists = true
						break
					}
				}
				if !namespaceExists {
					existingPool.Spec.AllocateTo.Namespaces = append(existingPool.Spec.AllocateTo.Namespaces, svc.Namespace)
					if err := r.metallbClient.UpdateIPAddressPool(context.Background(), existingPool); err != nil {
						return fmt.Errorf("failed to update IPAddressPool: %w", err)
					}
					logger.Infof("Successfully updated IPAddressPool %s with namespace %s", poolName, svc.Namespace)
				}
				// Skip the rest of the MetalLB resource creation since we're just updating the pool
				poolAlreadyExists = true
			} else if err != nil && !errors.IsNotFound(err) {
				// If error is not "not found", log it but continue to create the pool
				logger.Warnf("Failed to get IPAddressPool %s: %v, proceeding to create it", poolName, err)
			}
		}

		// Create MetalLB resources only if pool doesn't already exist
		var ipAddressPool *v1beta1.IPAddressPool
		if !poolAlreadyExists {
			// Determine the match labels
			matchLabels := make(map[string]string)
			if floatingIPGroup != "" {
				matchLabels["rancher.k8s.binbash.org/servicegroup"] = floatingIPGroup
			} else {
				matchLabels["rancher.k8s.binbash.org/service"] = svc.Name
				matchLabels["rancher.k8s.binbash.org/servicenamespace"] = svc.Namespace
			}
			ipAddressPool = &v1beta1.IPAddressPool{
				ObjectMeta: metav1.ObjectMeta{
					Name:      poolName,
					Namespace: r.appNamespace,
				},
				Spec: v1beta1.IPAddressPoolSpec{
					Addresses: []string{
						fmt.Sprintf("%s/32", allocatedIPAddress),
					},
					AllocateTo: &v1beta1.ServiceAllocation{
						Namespaces: []string{svc.Namespace},
						ServiceSelectors: []metav1.LabelSelector{
							{
								MatchLabels: matchLabels,
							},
						},
					},
				},
			}

			if err := r.metallbClient.CreateIPAddressPool(context.Background(), ipAddressPool); err != nil && !errors.IsAlreadyExists(err) {
				// if an IP is already a part of an existing IPAddressPool, it was not properly released, so we need to clean things up and try again
				if strings.Contains(err.Error(), "overlaps with already defined CIDR") {
					logger.Warnf("IP %s is already a part of an existing MetalLBIPAddressPool, trying to clean things up and try again", allocatedIPAddress)
					// get all IPAddressPools, loop through them and identify the CIDR that overlaps
					ipAddressPools, err := r.metallbClient.GetIPAddressPools(context.Background(), r.appNamespace)
					if err != nil {
						return fmt.Errorf("failed to get IPAddressPools: %w", err)
					}
					for _, p := range ipAddressPools {
						for _, a := range p.Spec.Addresses {
							if a == fmt.Sprintf("%s/32", allocatedIPAddress) {
								logger.Infof("CIDR %s/32 found in MetalLB IPAddressPool %s/%s, removing the old L2Advertisement and IPAddressPool", allocatedIPAddress, p.Namespace, p.Name)
								var releaseFIP bool = false
								if err := r.metallbClient.DeleteL2Advertisement(context.Background(), p.Name, r.appNamespace); err != nil {
									logger.Errorf("failed to delete L2Advertisement: %s", err)
									releaseFIP = true
								}
								if err := r.metallbClient.DeleteIPAddressPool(context.Background(), p.Name, r.appNamespace); err != nil {
									logger.Errorf("failed to delete IPAddressPool: %s", err)
									releaseFIP = true
								}
								if releaseFIP {
									errRelease := r.ipamClient.ReleaseFIP(
										string(secret.Data["clientSecret"]),
										string(secret.Data["cluster"]),
										string(secret.Data["project"]),
										fipPoolName,
										svc.Namespace,
										svc.Name,
										allocatedIPAddress,
										floatingIPGroup,
									)
									if errRelease != nil {
										return fmt.Errorf("failed to release FIP during CreateIPAddressPool cleanup: %v, original error: %w", errRelease, err)
									}
									return fmt.Errorf("failed to create IPAddressPool: %w", err)
								}
								logger.Infof("Successfully deleted the old MetalLB L2Advertisement and IPAddressPool %s/%s, trying to create a new one", r.appNamespace, ipAddressPool.Name)

								// Retry the creation of the IPAddressPool
								if err := r.metallbClient.CreateIPAddressPool(context.Background(), ipAddressPool); err != nil && !errors.IsAlreadyExists(err) {
									return fmt.Errorf("failed to create IPAddressPool: %w", err)
								}
								logger.Infof("Successfully created IPAddressPool %s/%s", r.appNamespace, poolName)
								break
							}
						}
					}
				} else {
					logger.Errorf("Failed to create MetalLB IPAddressPool: %s, releasing the FloatingIP", err)
					errRelease := r.ipamClient.ReleaseFIP(
						string(secret.Data["clientSecret"]),
						string(secret.Data["cluster"]),
						string(secret.Data["project"]),
						fipPoolName,
						svc.Namespace,
						svc.Name,
						allocatedIPAddress,
						floatingIPGroup,
					)
					if errRelease != nil {
						return fmt.Errorf("failed to release FIP during CreateIPAddressPool cleanup: %v, original error: %w", errRelease, err)
					}
					return fmt.Errorf("failed to create IPAddressPool: %w", err)
				}
			}

			l2Advertisement := &v1beta1.L2Advertisement{
				ObjectMeta: metav1.ObjectMeta{
					Name:      poolName,
					Namespace: r.appNamespace,
				},
				Spec: v1beta1.L2AdvertisementSpec{
					IPAddressPools: []string{poolName},
					Interfaces:     []string{networkInterface},
				},
			}
			if err := r.metallbClient.CreateL2Advertisement(context.Background(), l2Advertisement); err != nil && !errors.IsAlreadyExists(err) {
				logger.Errorf("Failed to create MetalLB L2Advertisement: %s, cleaning up and releasing the FloatingIP", err)
				errDelete := r.metallbClient.DeleteIPAddressPool(context.Background(), poolName, r.appNamespace)
				if errDelete != nil {
					return fmt.Errorf("failed to delete IPAddressPool during CreateL2Advertisement cleanup: %v, original error: %w", errDelete, err)
				}
				errRelease := r.ipamClient.ReleaseFIP(
					string(secret.Data["clientSecret"]),
					string(secret.Data["cluster"]),
					string(secret.Data["project"]),
					fipPoolName,
					svc.Namespace,
					svc.Name,
					allocatedIPAddress,
					floatingIPGroup,
				)
				if errRelease != nil {
					return fmt.Errorf("failed to release FIP during CreateL2Advertisement cleanup: %v, original error: %w", errRelease, err)
				}
				return fmt.Errorf("failed to create L2Advertisement: %w", err)
			}
		}
	} else if string(secret.Data["loadBalancerType"]) == "purelb" {
		// Create PureLB resources
		serviceGroup := &purelb.ServiceGroup{
			ObjectMeta: metav1.ObjectMeta{
				Name:      poolName,
				Namespace: r.appNamespace,
			},
			Spec: purelb.ServiceGroupSpec{
				Local: &purelb.ServiceGroupLocal{
					V4Pools: []purelb.AddressPool{
						{
							Aggregation: "default",
							Pool:        fmt.Sprintf("%s/32", allocatedIPAddress),
							Subnet:      subnet,
						},
					},
				},
			},
		}

		// Check if the floatingIPGroup is set and if the PureLB service group already exists
		// If so, skip creating a new ServiceGroup
		skipServiceGroupCreation := false
		if floatingIPGroup != "" {
			serviceGroups, err := r.purelbClient.GetServiceGroups(context.Background(), r.appNamespace)
			if err != nil {
				return fmt.Errorf("failed to get ServiceGroups: %w", err)
			}
			for _, sg := range serviceGroups {
				if sg.Name == poolName {
					logger.Infof("Found existing PureLB ServiceGroup %s/%s for floatingIPGroup %s, skipping creation", r.appNamespace, poolName, floatingIPGroup)
					skipServiceGroupCreation = true
					break
				}
			}
		}

		if !skipServiceGroupCreation {
			if err := r.purelbClient.CreateServiceGroup(context.Background(), serviceGroup); err != nil {
				logger.Errorf("Failed to create PureLB ServiceGroup: %s, releasing the FloatingIP", err)
				errRelease := r.ipamClient.ReleaseFIP(
					string(secret.Data["clientSecret"]),
					string(secret.Data["cluster"]),
					string(secret.Data["project"]),
					fipPoolName,
					svc.Namespace,
					svc.Name,
					allocatedIPAddress,
					floatingIPGroup,
				)
				if errRelease != nil {
					return fmt.Errorf("failed to release FIP during CreateServiceGroup cleanup: %v, original error: %w", errRelease, err)
				}
				return fmt.Errorf("failed to create ServiceGroup: %w", err)

			} else {
				logger.Infof("Successfully created PureLB ServiceGroup %s/%s", r.appNamespace, poolName)
			}

			// Not needed for now, but keeping the code here for future reference
			// sendGARP := true
			// lbNodeAgent := &purelb.LBNodeAgent{
			// 	ObjectMeta: metav1.ObjectMeta{
			// 		Name:      poolName,
			// 		Namespace: r.appNamespace,
			// 	},
			// 	Spec: purelb.LBNodeAgentSpec{
			// 		Local: &purelb.LBNodeAgentLocal{
			// 			LocalInt: networkInterface,
			// 			SendGARP: &sendGARP,
			// 		},
			// 	},
			// }
			// if err := r.purelbClient.CreateLBNodeAgent(context.Background(), lbNodeAgent); err != nil {
			// 	// Clean up the resources if the creation fails
			// 	return fmt.Errorf("failed to create PureLB LBNodeAgent: %w", err)
			// }

			// logger.Infof("Successfully created PureLB LBNodeAgent %s/%s", r.appNamespace, poolName)
		}
	}

	// Add finalizer, label and annotation to the service
	err = wait.PollImmediate(5*time.Second, 60*time.Second, func() (bool, error) {
		// Get the latest version of the service
		currentSvc, err := r.clientset.CoreV1().Services(svc.Namespace).Get(context.Background(), svc.Name, metav1.GetOptions{})
		if err != nil {
			if errors.IsNotFound(err) {
				logger.Debugf("Service '%s/%s' in work queue no longer exists", svc.Namespace, svc.Name)
				return true, nil
			}
			return false, err
		}

		finalizerPresent := containsString(currentSvc.ObjectMeta.Finalizers, finalizerName)
		serviceLabelValue, serviceLabelPresent := "", false
		if currentSvc.Labels != nil {
			serviceLabelValue, serviceLabelPresent = currentSvc.Labels["rancher.k8s.binbash.org/service"]
		}
		serviceNamespaceLabelValue, serviceNamespaceLabelPresent := "", false
		if currentSvc.Labels != nil {
			serviceNamespaceLabelValue, serviceNamespaceLabelPresent = currentSvc.Labels["rancher.k8s.binbash.org/servicenamespace"]
		}
		serviceGroupLabelValue, serviceGroupLabelPresent := "", false
		if currentSvc.Labels != nil {
			serviceGroupLabelValue, serviceGroupLabelPresent = currentSvc.Labels["rancher.k8s.binbash.org/servicegroup"]
		}
		fipAnnotationValue, fipAnnotationPresent := "", false
		if currentSvc.Annotations != nil {
			fipAnnotationValue, fipAnnotationPresent = currentSvc.Annotations["rancher.k8s.binbash.org/floatingip"]
		}
		fipGroupAnnotationValue, fipGroupAnnotationPresent := "", false
		if currentSvc.Annotations != nil {
			fipGroupAnnotationValue, fipGroupAnnotationPresent = currentSvc.Annotations["rancher.k8s.binbash.org/floatingip-group"]
		}

		var metallbAllowSharedIPValue string = ""
		var metallbAllowSharedIPPresent bool = false

		var serviceGroupAnnotationValue string = ""
		var serviceGroupAnnotationPresent bool = false
		var purelbAllowSharedIPValue string = ""
		var purelbAllowSharedIPPresent bool = false

		if string(secret.Data["loadBalancerType"]) == "metallb" {
			if currentSvc.Annotations != nil {
				metallbAllowSharedIPValue, metallbAllowSharedIPPresent = currentSvc.Annotations["metallb.io/allow-shared-ip"]
			}

			// Check if fipGroupAnnotationPresent and sharedKey is not empty
			if fipGroupAnnotationPresent && fipGroupAnnotationValue != "" && sharedKey != "" {
				// Check if currentSvc.Annotations["metallb.io/allow-shared-ip"] == "sharedKey"
				if metallbAllowSharedIPPresent && metallbAllowSharedIPValue == sharedKey {
					if floatingIPGroup != "" {
						if finalizerPresent && serviceGroupLabelPresent && serviceGroupLabelValue == floatingIPGroup &&
							serviceLabelPresent && serviceLabelValue == currentSvc.Name && serviceNamespaceLabelPresent &&
							serviceNamespaceLabelValue == svc.Namespace && fipAnnotationPresent && fipAnnotationValue == allocatedIPAddress {
							*svc = *currentSvc
							return true, nil
						}
					} else {
						if finalizerPresent && serviceLabelPresent && serviceLabelValue == currentSvc.Name && serviceNamespaceLabelPresent &&
							serviceNamespaceLabelValue == svc.Namespace && fipAnnotationPresent && fipAnnotationValue == allocatedIPAddress {
							*svc = *currentSvc
							return true, nil
						}
					}
				}
			} else {
				if finalizerPresent && serviceLabelPresent && serviceLabelValue == currentSvc.Name && serviceNamespaceLabelPresent &&
					serviceNamespaceLabelValue == svc.Namespace && fipAnnotationPresent && fipAnnotationValue == allocatedIPAddress {
					*svc = *currentSvc
					return true, nil
				}
			}
		} else if string(secret.Data["loadBalancerType"]) == "purelb" {
			if currentSvc.Annotations != nil {
				serviceGroupAnnotationValue, serviceGroupAnnotationPresent = currentSvc.Annotations["purelb.io/service-group"]
				purelbAllowSharedIPValue, purelbAllowSharedIPPresent = currentSvc.Annotations["purelb.io/allow-shared-ip"]
			}

			// Check if fipGroupAnnotationPresent and sharedKey is not empty
			if fipGroupAnnotationPresent && fipGroupAnnotationValue != "" && sharedKey != "" {
				// Check if currentSvc.Annotations["purelb.io/allow-shared-ip"] == "sharedKey"
				if purelbAllowSharedIPPresent && purelbAllowSharedIPValue == sharedKey {
					if floatingIPGroup != "" {
						if finalizerPresent && serviceGroupLabelPresent && serviceGroupLabelValue == floatingIPGroup &&
							serviceLabelPresent && serviceLabelValue == currentSvc.Name && serviceNamespaceLabelPresent &&
							serviceNamespaceLabelValue == svc.Namespace && fipAnnotationPresent && fipAnnotationValue == allocatedIPAddress &&
							serviceGroupAnnotationPresent && serviceGroupAnnotationValue == poolName {
							*svc = *currentSvc
							return true, nil
						}
					} else {
						if finalizerPresent && serviceLabelPresent && serviceLabelValue == currentSvc.Name && serviceNamespaceLabelPresent &&
							serviceNamespaceLabelValue == svc.Namespace && fipAnnotationPresent && fipAnnotationValue == allocatedIPAddress &&
							serviceGroupAnnotationPresent && serviceGroupAnnotationValue == poolName {
							*svc = *currentSvc
							return true, nil
						}
					}
				}
			} else {
				if finalizerPresent && serviceLabelPresent && serviceLabelValue == currentSvc.Name && serviceNamespaceLabelPresent &&
					serviceNamespaceLabelValue == svc.Namespace && fipAnnotationPresent && fipAnnotationValue == allocatedIPAddress &&
					serviceGroupAnnotationPresent && serviceGroupAnnotationValue == poolName {
					*svc = *currentSvc
					return true, nil
				}
			}
		} else {
			if finalizerPresent && serviceLabelPresent && serviceLabelValue == currentSvc.Name && serviceNamespaceLabelPresent &&
				serviceNamespaceLabelValue == svc.Namespace && fipAnnotationPresent && fipAnnotationValue == allocatedIPAddress {
				*svc = *currentSvc
				return true, nil
			}
		}

		svcToUpdate := currentSvc.DeepCopy()
		needsUpdate := false

		if svcToUpdate.Labels == nil {
			svcToUpdate.Labels = make(map[string]string)
		}
		if !serviceLabelPresent || serviceLabelValue != svcToUpdate.Name {
			svcToUpdate.Labels["rancher.k8s.binbash.org/service"] = svcToUpdate.Name
			needsUpdate = true
		}
		if !serviceNamespaceLabelPresent || serviceNamespaceLabelValue != svcToUpdate.Namespace {
			svcToUpdate.Labels["rancher.k8s.binbash.org/servicenamespace"] = svcToUpdate.Namespace
			needsUpdate = true
		}
		if floatingIPGroup != "" && (!serviceGroupLabelPresent || serviceGroupLabelValue != floatingIPGroup) {
			svcToUpdate.Labels["rancher.k8s.binbash.org/servicegroup"] = floatingIPGroup
			needsUpdate = true
		}

		if svcToUpdate.Annotations == nil {
			svcToUpdate.Annotations = make(map[string]string)
		}
		if !fipAnnotationPresent || fipAnnotationValue != allocatedIPAddress {
			svcToUpdate.Annotations["rancher.k8s.binbash.org/floatingip"] = allocatedIPAddress
			needsUpdate = true
		}

		if string(secret.Data["loadBalancerType"]) == "metallb" {
			// Add sharedKey annotation if fipGroupAnnotationPresent and sharedKey is not empty
			if fipGroupAnnotationPresent && fipGroupAnnotationValue != "" && sharedKey != "" {
				if !metallbAllowSharedIPPresent || metallbAllowSharedIPValue != sharedKey {
					svcToUpdate.Annotations["metallb.io/allow-shared-ip"] = sharedKey
					needsUpdate = true
				}
			}
		} else if string(secret.Data["loadBalancerType"]) == "purelb" {
			if !serviceGroupAnnotationPresent || serviceGroupAnnotationValue != poolName {
				svcToUpdate.Annotations["purelb.io/service-group"] = poolName
				needsUpdate = true
			}
			// Add sharedKey annotation if fipGroupAnnotationPresent and sharedKey is not empty
			if fipGroupAnnotationPresent && fipGroupAnnotationValue != "" && sharedKey != "" {
				if !purelbAllowSharedIPPresent || purelbAllowSharedIPValue != sharedKey {
					svcToUpdate.Annotations["purelb.io/allow-shared-ip"] = sharedKey
					needsUpdate = true
				}
			}
		}

		if !finalizerPresent {
			svcToUpdate.ObjectMeta.Finalizers = append(svcToUpdate.ObjectMeta.Finalizers, finalizerName)
			needsUpdate = true
		}

		if !needsUpdate {
			*svc = *currentSvc
			return true, nil
		}

		_, err = r.clientset.CoreV1().Services(svcToUpdate.Namespace).Update(context.Background(), svcToUpdate, metav1.UpdateOptions{})
		if err == nil {
			*svc = *svcToUpdate
			return true, nil
		}

		if errors.IsConflict(err) {
			logger.Info("Service modified, retrying to add finalizer, label and annotation")
			return false, nil
		}

		return false, err
	})

	if err != nil {
		if string(secret.Data["loadBalancerType"]) == "metallb" {
			errDeleteAdv := r.metallbClient.DeleteL2Advertisement(context.Background(), poolName, r.appNamespace)
			if errDeleteAdv != nil {
				return fmt.Errorf("failed to delete L2Advertisement during finalizer update cleanup: %v, original error: %w", errDeleteAdv, err)
			}
			errDeletePool := r.metallbClient.DeleteIPAddressPool(context.Background(), poolName, r.appNamespace)
			if errDeletePool != nil {
				return fmt.Errorf("failed to delete IPAddressPool during finalizer update cleanup: %v, original error: %w", errDeletePool, err)
			}
		} else if string(secret.Data["loadBalancerType"]) == "purelb" {
			errDeleteServiceGroup := r.purelbClient.DeleteServiceGroup(context.Background(), poolName, r.appNamespace)
			if errDeleteServiceGroup != nil {
				return fmt.Errorf("failed to delete ServiceGroup during finalizer update cleanup: %v, original error: %w", errDeleteServiceGroup, err)
			}
			// Not needed for now, but keeping the code here for future reference
			// errDeleteLBNodeAgent := r.purelbClient.DeleteLBNodeAgent(context.Background(), poolName, r.appNamespace)
			// if errDeleteLBNodeAgent != nil {
			// 	return fmt.Errorf("failed to delete LBNodeAgent during finalizer update cleanup: %v, original error: %w", errDeleteLBNodeAgent, err)
			// }
		}
		errRelease := r.ipamClient.ReleaseFIP(
			string(secret.Data["clientSecret"]),
			string(secret.Data["cluster"]),
			string(secret.Data["project"]),
			fipPoolName,
			svc.Namespace,
			svc.Name,
			allocatedIPAddress,
			floatingIPGroup,
		)
		if errRelease != nil {
			return fmt.Errorf("failed to release FIP during finalizer update cleanup: %v, original error: %w", errRelease, err)
		}
		return fmt.Errorf("failed to add finalizer, label and annotation to service %s/%s: %w", svc.Namespace, svc.Name, err)
	}

	return nil
}

func (c *Controller) addFunc(obj interface{}) {
	service, ok := obj.(*v1.Service)
	if !ok {
		return
	}

	if service.Spec.Type == v1.ServiceTypeLoadBalancer {
		key, err := cache.MetaNamespaceKeyFunc(service)
		if err == nil {
			c.queue.Add(key)
		}
	}
}

func (c *Controller) updateFunc(old, new interface{}) {
	service, ok := new.(*v1.Service)
	if !ok {
		return
	}

	if service.Spec.Type == v1.ServiceTypeLoadBalancer && service.ObjectMeta.DeletionTimestamp != nil {
		key, err := cache.MetaNamespaceKeyFunc(service)
		if err == nil {
			c.queue.Add(key)
		}
	}
}

func (c *Controller) deleteFunc(obj interface{}) {
	service, ok := obj.(*v1.Service)
	if !ok {
		return
	}

	key, err := cache.MetaNamespaceKeyFunc(service)
	if err == nil {
		c.queue.Add(key)
	}
}

func containsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}

func removeString(slice []string, s string) []string {
	for i, item := range slice {
		if item == s {
			return append(slice[:i], slice[i+1:]...)
		}
	}
	return slice
}
