package k8s

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
	"log"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type PodInfo struct {
	Name      string
	Namespace string
}

type PodMapper struct {
	client    *kubernetes.Clientset
	nodeName  string
	cache     map[string]*podCacheEntry
	cacheLock sync.RWMutex
	ttl       time.Duration
}

type podCacheEntry struct {
	info      *PodInfo
	expiresAt time.Time
}

func NewPodMapper(ttl time.Duration) (*PodMapper, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to get in-cluster config: %w", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create kubernetes client: %w", err)
	}

	nodeName := os.Getenv("NODE_NAME")
	if nodeName == "" {
		// Fallback to hostname if NODE_NAME is not set (useful for local testing)
		hostname, _ := os.Hostname()
		nodeName = hostname
	}

	return &PodMapper{
		client:   clientset,
		nodeName: nodeName,
		cache:    make(map[string]*podCacheEntry),
		ttl:      ttl,
	}, nil
}

// GetPodByTGID resolves a TGID to a Pod using /proc/<tgid>/cgroup and K8s API
func (m *PodMapper) GetPodByTGID(tgid uint32) (*PodInfo, error) {
	containerID, err := m.getContainerID(tgid)
	if err != nil {
		return nil, err
	}

	return m.getPodByContainerID(containerID)
}

// getContainerID parses /proc/<tgid>/cgroup to find the container ID
func (m *PodMapper) getContainerID(tgid uint32) (string, error) {
	path := fmt.Sprintf("/proc/%d/cgroup", tgid)
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		// log.Printf("[DEBUG] Parsing cgroup line: %s", line)
		
		if strings.Contains(line, "cri-containerd-") {
			parts := strings.Split(line, "cri-containerd-")
			if len(parts) > 1 {
				id := strings.TrimSuffix(parts[1], ".scope")
				log.Printf("[DEBUG] Extracted containerd ID: %s", id)
				return id, nil
			}
		}
		if strings.Contains(line, "docker-") {
			parts := strings.Split(line, "docker-")
			if len(parts) > 1 {
				id := strings.TrimSuffix(parts[1], ".scope")
				return id, nil
			}
		}
		// Generic CRI-O/Standard pattern sometimes just has the ID at the end
		if strings.Contains(line, "kubepods") {
			parts := strings.Split(line, "/")
			lastPart := parts[len(parts)-1]
			if len(lastPart) > 60 { // Likely a long hex ID
				return lastPart, nil
			}
		}
	}

	return "", fmt.Errorf("container ID not found in %s", path)
}

func (m *PodMapper) getPodByContainerID(containerID string) (*PodInfo, error) {
	m.cacheLock.RLock()
	entry, ok := m.cache[containerID]
	m.cacheLock.RUnlock()

	if ok && time.Now().Before(entry.expiresAt) {
		return entry.info, nil
	}

	// Cache miss or expired, query K8s API
	pod, err := m.queryK8sForContainer(containerID)
	if err != nil {
		return nil, err
	}

	info := &PodInfo{
		Name:      pod.Name,
		Namespace: pod.Namespace,
	}

	m.cacheLock.Lock()
	m.cache[containerID] = &podCacheEntry{
		info:      info,
		expiresAt: time.Now().Add(m.ttl),
	}
	m.cacheLock.Unlock()

	return info, nil
}

func (m *PodMapper) queryK8sForContainer(containerID string) (*corev1.Pod, error) {
	log.Printf("[DEBUG] Querying K8s for container ID: %s on node: %s", containerID, m.nodeName)
	// We sweep all pods on this node
	pods, err := m.client.CoreV1().Pods("").List(context.Background(), metav1.ListOptions{
		FieldSelector: fmt.Sprintf("spec.nodeName=%s", m.nodeName),
	})
	if err != nil {
		return nil, err
	}

	for _, pod := range pods.Items {
		for _, status := range pod.Status.ContainerStatuses {
			// log.Printf("[DEBUG] Checking Pod %s Container %s", pod.Name, status.ContainerID)
			// containerID in K8s Status is usually "containerd://<hex>" or "docker://<hex>"
			if strings.Contains(status.ContainerID, containerID) {
				log.Printf("[DEBUG] Found match: Pod %s", pod.Name)
				return &pod, nil
			}
		}
	}

	return nil, fmt.Errorf("pod not found for container ID %s on node %s", containerID, m.nodeName)
}
