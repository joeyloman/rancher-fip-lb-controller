package controller

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/joeyloman/rancher-fip-lb-controller/pkg/ipam"
	"github.com/joeyloman/rancher-fip-lb-controller/pkg/metallb"
	"github.com/rancher/lasso/pkg/log"
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
	serviceInformer cache.SharedIndexInformer
	queue           workqueue.RateLimitingInterface
	reconciler      *reconciler
	recorder        record.EventRecorder
}

// New creates a new controller.
func New(clientset kubernetes.Interface, metallbClient *metallb.Client, appNamespace string, caCertData []byte) *Controller {
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
		serviceInformer: serviceInformer,
		queue:           queue,
		recorder:        recorder,
	}
	c.reconciler = &reconciler{
		clientset:     clientset,
		metallbClient: metallbClient,
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
	RequestFIP(clientSecret, cluster, project, floatingIPPool, serviceNamespace, serviceName, ipaddr string) (string, error)
	ReleaseFIP(clientSecret, cluster, project, floatingIPPool, serviceNamespace, serviceName, ipaddr string) error
}

type metallbClient interface {
	CreateIPAddressPool(ctx context.Context, pool *v1beta1.IPAddressPool) error
	CreateL2Advertisement(ctx context.Context, ad *v1beta1.L2Advertisement) error
	DeleteIPAddressPool(ctx context.Context, name, namespace string) error
	DeleteL2Advertisement(ctx context.Context, name, namespace string) error
	GetIPAddressPools(ctx context.Context, namespace string) ([]v1beta1.IPAddressPool, error)
}

// reconciler reconciles a Service object
type reconciler struct {
	clientset     kubernetes.Interface
	metallbClient metallbClient
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
		return "", fmt.Errorf("failed to get namespace %s: %w", r.appNamespace, err)
	}
	projectId, ok := appNs.Labels["rancher.k8s.binbash.org/project-name"]
	if !ok {
		logrus.Infof("Namespace %s does not have a project ID label, skipping", r.appNamespace)
		return "", nil
	}
	return projectId, nil
}

func (r *reconciler) reconcile(svc *v1.Service) error {
	var ipAddress string

	logrus.WithFields(logrus.Fields{
		"service":    fmt.Sprintf("%s/%s", svc.Namespace, svc.Name),
		"serviceUID": svc.UID,
	})

	// Handle service deletion
	if svc.ObjectMeta.DeletionTimestamp != nil {
		if containsString(svc.ObjectMeta.Finalizers, finalizerName) {
			ns, err := r.clientset.CoreV1().Namespaces().Get(context.Background(), svc.Namespace, metav1.GetOptions{})
			if err != nil {
				return fmt.Errorf("failed to get namespace %s: %w", svc.Namespace, err)
			}

			// Check if the namespace if part of a project, if not check if the cluster is part of a project
			var projectId string
			var ok bool
			projectId, ok = ns.Labels["field.cattle.io/projectId"]
			if !ok {
				logrus.Infof("Service namespace %s does not have a project ID label, checking if the cluster is part of a project", svc.Namespace)

				var err error
				projectId, err = r.getProjectIDFromAppNamespace()
				if err != nil {
					return err
				}
				if projectId == "" {
					return nil
				}
			}

			// Create a new IPAM client
			secretName := fmt.Sprintf("rancher-fip-config-%s", projectId)
			secret, err := r.clientset.CoreV1().Secrets(r.appNamespace).Get(context.Background(), secretName, metav1.GetOptions{})
			if err != nil {
				if errors.IsNotFound(err) {
					logrus.Warnf("Secret %s not found in namespace %s, skipping", secretName, r.appNamespace)
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

				err = r.ipamClient.ReleaseFIP(
					string(secret.Data["clientSecret"]),
					string(secret.Data["cluster"]),
					string(secret.Data["project"]),
					string(secret.Data["floatingIPPool"]),
					svc.Namespace,
					svc.Name,
					ipAddress,
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

					logrus.Warnf("Failed to remove floatingip annotation from service %s/%s, will retry: %v", currentSvc.Namespace, currentSvc.Name, err)
					return false, nil
				})
				if err != nil {
					return fmt.Errorf("failed to remove floatingip annotation from service %s/%s: %w", svc.Namespace, svc.Name, err)
				}

				logrus.Infof("Successfully released FIP %s", ipAddress)
			}

			// Delete MetalLB resources
			poolName := fmt.Sprintf("rancher-fip-%s-%s", svc.Namespace, svc.Name)
			if err := r.metallbClient.DeleteIPAddressPool(context.Background(), poolName, r.appNamespace); err != nil && !errors.IsNotFound(err) {
				return fmt.Errorf("failed to delete IPAddressPool %s: %w", poolName, err)
			}
			if err := r.metallbClient.DeleteL2Advertisement(context.Background(), poolName, r.appNamespace); err != nil && !errors.IsNotFound(err) {
				return fmt.Errorf("failed to delete L2Advertisement %s: %w", poolName, err)
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
					logrus.Warnf("Failed to remove finalizer from service %s/%s, will retry: %v", currentSvc.Namespace, currentSvc.Name, err)
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

	logrus.Infof("Reconciling Service")

	// Check if the service already has a load balancer IP
	if len(svc.Status.LoadBalancer.Ingress) > 0 {
		logrus.Infof("Service %s/%s already has a load balancer IP, skipping", svc.Namespace, svc.Name)
		return nil
	}

	ns, err := r.clientset.CoreV1().Namespaces().Get(context.Background(), svc.Namespace, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to get namespace %s: %w", svc.Namespace, err)
	}

	// Check if the namespace if part of a project, if not check if the cluster is part of a project
	var projectId string
	var ok bool
	projectId, ok = ns.Labels["field.cattle.io/projectId"]
	if !ok {
		logrus.Infof("Service namespace %s does not have a project ID label, checking if the cluster is part of a project", svc.Namespace)

		var err error
		projectId, err = r.getProjectIDFromAppNamespace()
		if err != nil {
			return err
		}
		if projectId == "" {
			return nil
		}
	}

	logrus.WithField("projectID", projectId)
	logrus.Infof("Service is in project")

	// Construct the secret name and get the secret
	secretName := fmt.Sprintf("rancher-fip-config-%s", projectId)
	secret, err := r.clientset.CoreV1().Secrets(r.appNamespace).Get(context.Background(), secretName, metav1.GetOptions{})
	if err != nil {
		if errors.IsNotFound(err) {
			logrus.Warnf("Secret %s not found in namespace %s, skipping", secretName, r.appNamespace)
			return nil
		}
		return fmt.Errorf("failed to get secret %s: %w", secretName, err)
	}

	logrus.Infof("Successfully fetched secret %s", secret.Name)

	// Generate a client ID
	clientId := fmt.Sprintf("client-%s", string(secret.Data["cluster"]))

	// Get the network-interface-mappings configmap
	configMap, err := r.clientset.CoreV1().ConfigMaps(r.appNamespace).Get(context.Background(), "network-interface-mappings", metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to get configmap network-interface-mappings: %w", err)
	}

	// Look up the network interface
	networkInterface, ok := configMap.Data[string(secret.Data["floatingIPPool"])]
	if !ok {
		return fmt.Errorf("no network interface found for floating ip pool %s", string(secret.Data["floatingIPPool"]))
	}
	logrus.Infof("Found network interface %s for floating ip pool %s", networkInterface, string(secret.Data["floatingIPPool"]))

	// Check if a static IP is given in the service annotations
	ipAddress = svc.Annotations["rancher.k8s.binbash.org/static-ip"]
	if ipAddress != "" {
		logrus.Infof("Found request for static IP %s for service %s/%s", ipAddress, svc.Namespace, svc.Name)
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
	allocatedIPAddress, err := r.ipamClient.RequestFIP(
		string(secret.Data["clientSecret"]),
		string(secret.Data["cluster"]),
		string(secret.Data["project"]),
		string(secret.Data["floatingIPPool"]),
		svc.Namespace,
		svc.Name,
		ipAddress,
	)
	if err != nil {
		if strings.Contains(err.Error(), "quota exceeded") {
			logrus.Infof("failed to request FIP: quota exceeded for project %s service %s/%s, skipping", string(secret.Data["project"]), svc.Namespace, svc.Name)
			r.recorder.Eventf(svc, v1.EventTypeWarning, "QuotaExceeded", "Failed to request FloatingIP for Service Load Balancer: quota exceeded for project %s", string(secret.Data["project"]))
			return nil
		}
		if strings.Contains(err.Error(), "denied the request") {
			logrus.Errorf("%s", err)
			r.recorder.Eventf(svc, v1.EventTypeWarning, "RequestDenied", "Failed to request FloatingIP for Service Load Balancer: request denied for project %s", string(secret.Data["project"]))
			return nil
		}
		return fmt.Errorf("failed to request FIP: %w", err)
	}
	logrus.Infof("Successfully requested FIP %s", allocatedIPAddress)

	// Create MetalLB resources
	poolName := fmt.Sprintf("rancher-fip-%s-%s", svc.Namespace, svc.Name)
	ipAddressPool := &v1beta1.IPAddressPool{
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
						MatchLabels: map[string]string{
							"rancher.k8s.binbash.org/service":          svc.Name,
							"rancher.k8s.binbash.org/servicenamespace": svc.Namespace,
						},
					},
				},
			},
		},
	}

	if err := r.metallbClient.CreateIPAddressPool(context.Background(), ipAddressPool); err != nil && !errors.IsAlreadyExists(err) {
		// if an IP is already a part of an existing IPAddressPool, it was not properly released, so we need to clean things up and try again
		if strings.Contains(err.Error(), "overlaps with already defined CIDR") {
			logrus.Warnf("IP %s is already a part of an existing MetalLBIPAddressPool, trying to clean things up and try again", allocatedIPAddress)
			// get all IPAddressPools, loop through them and identify the CIDR that overlaps
			ipAddressPools, err := r.metallbClient.GetIPAddressPools(context.Background(), r.appNamespace)
			if err != nil {
				return fmt.Errorf("failed to get IPAddressPools: %w", err)
			}
			for _, p := range ipAddressPools {
				for _, a := range p.Spec.Addresses {
					if a == fmt.Sprintf("%s/32", allocatedIPAddress) {
						logrus.Infof("CIDR %s/32 found in MetalLB IPAddressPool %s/%s, removing the old L2Advertisement and IPAddressPool", allocatedIPAddress, p.Namespace, p.Name)
						var releaseFIP bool = false
						if err := r.metallbClient.DeleteL2Advertisement(context.Background(), p.Name, r.appNamespace); err != nil {
							logrus.Errorf("failed to delete L2Advertisement: %s", err)
							releaseFIP = true
						}
						if err := r.metallbClient.DeleteIPAddressPool(context.Background(), p.Name, r.appNamespace); err != nil {
							logrus.Errorf("failed to delete IPAddressPool: %s", err)
							releaseFIP = true
						}
						if releaseFIP {
							errRelease := r.ipamClient.ReleaseFIP(
								string(secret.Data["clientSecret"]),
								string(secret.Data["cluster"]),
								string(secret.Data["project"]),
								string(secret.Data["floatingIPPool"]),
								svc.Namespace,
								svc.Name,
								allocatedIPAddress,
							)
							if errRelease != nil {
								return fmt.Errorf("failed to release FIP during CreateIPAddressPool cleanup: %v, original error: %w", errRelease, err)
							}
							return fmt.Errorf("failed to create IPAddressPool: %w", err)
						}
						logrus.Infof("Successfully deleted the old MetalLB L2Advertisement and IPAddressPool %s/%s, trying to create a new one", r.appNamespace, ipAddressPool.Name)

						// Retry the creation of the IPAddressPool
						if err := r.metallbClient.CreateIPAddressPool(context.Background(), ipAddressPool); err != nil && !errors.IsAlreadyExists(err) {
							return fmt.Errorf("failed to create IPAddressPool: %w", err)
						}
						logrus.Infof("Successfully created IPAddressPool %s/%s", r.appNamespace, poolName)
						break
					}
				}
			}
		} else {
			log.Errorf("Failed to create MetalLB IPAddressPool: %s, releasing the FloatingIP", err)
			errRelease := r.ipamClient.ReleaseFIP(
				string(secret.Data["clientSecret"]),
				string(secret.Data["cluster"]),
				string(secret.Data["project"]),
				string(secret.Data["floatingIPPool"]),
				svc.Namespace,
				svc.Name,
				allocatedIPAddress,
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
		log.Errorf("Failed to create MetalLB L2Advertisement: %s, cleaning up and releasing the FloatingIP", err)
		errDelete := r.metallbClient.DeleteIPAddressPool(context.Background(), poolName, r.appNamespace)
		if errDelete != nil {
			return fmt.Errorf("failed to delete IPAddressPool during CreateL2Advertisement cleanup: %v, original error: %w", errDelete, err)
		}
		errRelease := r.ipamClient.ReleaseFIP(
			string(secret.Data["clientSecret"]),
			string(secret.Data["cluster"]),
			string(secret.Data["project"]),
			string(secret.Data["floatingIPPool"]),
			svc.Namespace,
			svc.Name,
			allocatedIPAddress,
		)
		if errRelease != nil {
			return fmt.Errorf("failed to release FIP during CreateL2Advertisement cleanup: %v, original error: %w", errRelease, err)
		}
		return fmt.Errorf("failed to create L2Advertisement: %w", err)
	}

	// Add finalizer, label and annotation to the service
	err = wait.PollImmediate(5*time.Second, 60*time.Second, func() (bool, error) {
		// Get the latest version of the service
		currentSvc, err := r.clientset.CoreV1().Services(svc.Namespace).Get(context.Background(), svc.Name, metav1.GetOptions{})
		if err != nil {
			if errors.IsNotFound(err) {
				logrus.Debugf("Service '%s/%s' in work queue no longer exists", svc.Namespace, svc.Name)
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
		annotationValue, annotationPresent := "", false
		if currentSvc.Annotations != nil {
			annotationValue, annotationPresent = currentSvc.Annotations["rancher.k8s.binbash.org/floatingip"]
		}

		if finalizerPresent && serviceLabelPresent && serviceLabelValue == currentSvc.Name && serviceNamespaceLabelPresent && serviceNamespaceLabelValue == svc.Namespace && annotationPresent && annotationValue == allocatedIPAddress {
			*svc = *currentSvc
			return true, nil
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

		if svcToUpdate.Annotations == nil {
			svcToUpdate.Annotations = make(map[string]string)
		}
		if !annotationPresent || annotationValue != allocatedIPAddress {
			svcToUpdate.Annotations["rancher.k8s.binbash.org/floatingip"] = allocatedIPAddress
			needsUpdate = true
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
			logrus.Info("Service modified, retrying to add finalizer, label and annotation")
			return false, nil
		}

		return false, err
	})

	if err != nil {
		errDeleteAdv := r.metallbClient.DeleteL2Advertisement(context.Background(), poolName, r.appNamespace)
		if errDeleteAdv != nil {
			return fmt.Errorf("failed to delete L2Advertisement during finalizer update cleanup: %v, original error: %w", errDeleteAdv, err)
		}
		errDeletePool := r.metallbClient.DeleteIPAddressPool(context.Background(), poolName, r.appNamespace)
		if errDeletePool != nil {
			return fmt.Errorf("failed to delete IPAddressPool during finalizer update cleanup: %v, original error: %w", errDeletePool, err)
		}
		errRelease := r.ipamClient.ReleaseFIP(
			string(secret.Data["clientSecret"]),
			string(secret.Data["cluster"]),
			string(secret.Data["project"]),
			string(secret.Data["floatingIPPool"]),
			svc.Namespace,
			svc.Name,
			allocatedIPAddress,
		)
		if errRelease != nil {
			return fmt.Errorf("failed to release FIP during finalizer update cleanup: %v, original error: %w", errRelease, err)
		}
		return fmt.Errorf("failed to add finalizer, label and annotation to service %s/%s: %w", svc.Namespace, svc.Name, err)
	}

	// We'll add more logic here

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
