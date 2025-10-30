# rancher-fip-lb-controller

## Overview

The `rancher-fip-lb-controller` is a Kubernetes controller that manages MetalLB `IPAddressPool` and `L2Advertisement` resources based on `LoadBalancer` services in a Rancher-managed cluster. It integrates with an external IPAM solution to request and release floating IP addresses.

## Building the Controller

To build the Docker image, run the following command from the root of the repository:

```sh
docker build -t joeyloman/rancher-fip-lb-controller:latest .
```

## Deploying the Controller

### Using `kubectl`

Create the application namespace (if it doesn't exist yet), then apply the manifests from the `deployments` directory:

```sh
kubectl create namespace rancher-fip-manager
kubectl apply -f deployments/deployment.yaml
```

This will create the following resources in the `rancher-fip-manager` namespace:
-   A `rancher-fip-lb-controller` `ServiceAccount`.
-   A `ClusterRole` and `ClusterRoleBinding` with the necessary permissions.
-   A `Role` and `RoleBinding` for Secrets access within the namespace.
-   A `Deployment` for the controller.

## Configuration

The controller is configured via a `Secret` and a `ConfigMap` in the `rancher-fip-manager` namespace.

### Project detection

The controller determines the Rancher project ID as follows:
-   First, it checks the `field.cattle.io/projectId` label on the Service's namespace.
-   If not present, it falls back to the `rancher.k8s.binbash.org/project-name` label on the controller's app namespace (`rancher-fip-manager`).

For HTTP server enablement and the fallback to work, label the app namespace:

```sh
kubectl label namespace rancher-fip-manager rancher.k8s.binbash.org/project-name=<project-id>
```

### IPAM Configuration

For each Rancher project that will use the controller, you must create a `Secret` with the following format:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: rancher-fip-config-<project-id> # e.g. rancher-fip-config-p-12345
  namespace: rancher-fip-manager
stringData:
  apiUrl: "http://your-ipam-api"
  clientSecret: "your-client-secret"
  cluster: "your-cluster-name"
  project: "your-project-name"
  floatingIPPool: "your-fip-pool"
```

## Service Annotations and Labels

To request a specific static IP address for a `LoadBalancer` service, add the following annotation to your service manifest:

```yaml
metadata:
  annotations:
    rancher.k8s.binbash.org/static-ip: "<ip-address>"
```

The controller will add the following annotations and labels to the service after requesting the floating IP:

- Annotation `rancher.k8s.binbash.org/floatingip`: The allocated floating IP address.
- Label `rancher.k8s.binbash.org/service`: The name of the service.
- Label `rancher.k8s.binbash.org/servicenamespace`: The namespace of the service.

The controller also adds a finalizer `rancher.k8s.binbash.org/floatingip-cleanup` to the service to ensure proper cleanup of resources when the service is deleted.

## Network Interface Mappings

You must create a `ConfigMap` in the `rancher-fip-manager` namespace that maps floating IP pools to network interfaces for MetalLB's `L2Advertisement`.

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: network-interface-mappings
  namespace: rancher-fip-manager
data:
  # <floating_ip_pool_name>: <network_interface>
  pool1: eth0
  pool2: eth1
```
