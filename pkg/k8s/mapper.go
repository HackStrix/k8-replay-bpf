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
	"syscall"

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
	netnsCache map[uint32]string // netnsID -> containerID
	cacheLock sync.RWMutex
	ttl       time.Duration
	procPath  string
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

	procPath := "/proc"
	if _, err := os.Stat("/host/proc"); err == nil {
		procPath = "/host/proc"
		log.Printf("[INFO] Using host proc path: %s", procPath)
	}

	return &PodMapper{
		client:     clientset,
		nodeName:   nodeName,
		cache:      make(map[string]*podCacheEntry),
		netnsCache: make(map[uint32]string),
		ttl:        ttl,
		procPath:   procPath,
	}, nil
}

// GetPodByNetnsID resolves a Network Namespace Inode to a Pod
func (m *PodMapper) GetPodByNetnsID(netnsID uint32) (*PodInfo, error) {
	containerID, podUID, err := m.getIdentifiersByNetns(netnsID)
	if err != nil {
		return nil, err
	}

	return m.getPodByIdentifiers(containerID, podUID)
}

func (m *PodMapper) getIdentifiersByNetns(netnsID uint32) (string, string, error) {
	m.cacheLock.RLock()
	id, ok := m.netnsCache[netnsID]
	m.cacheLock.RUnlock()
	if ok {
		// For simplicity, we only cache the containerID for now,
		// but we might need to cache podUID too if lookups fail.
		return id, "", nil
	}

	// Walk proc to find the netns
	log.Printf("[DEBUG] Walking %s to find netns %d", m.procPath, netnsID)
	entries, err := os.ReadDir(m.procPath)
	if err != nil {
		return "", "", err
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid := entry.Name()
		// Check if it's a number
		if pid[0] < '0' || pid[0] > '9' {
			continue
		}

		nsPath := fmt.Sprintf("%s/%s/ns/net", m.procPath, pid)
		var st syscall.Stat_t
		if err := syscall.Stat(nsPath, &st); err != nil {
			continue
		}

		if uint32(st.Ino) == netnsID {
			log.Printf("[DEBUG] Found PID %s for netns %d", pid, netnsID)
			// Now get identifiers from cgroup
			tgid := 0
			fmt.Sscanf(pid, "%d", &tgid)
			containerID, podUID, err := m.getIdentifiers(uint32(tgid))
			if err == nil {
				m.cacheLock.Lock()
				m.netnsCache[netnsID] = containerID
				m.cacheLock.Unlock()
				return containerID, podUID, nil
			}
		}
	}

	return "", "", fmt.Errorf("netns %d not found in %s", netnsID, m.procPath)
}

// getIdentifiers parses cgroup to find both container ID and Pod UID
func (m *PodMapper) getIdentifiers(tgid uint32) (string, string, error) {
	path := fmt.Sprintf("%s/%d/cgroup", m.procPath, tgid)
	file, err := os.Open(path)
	if err != nil {
		return "", "", err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var containerID, podUID string
	for scanner.Scan() {
		line := scanner.Text()
		
		// Extract Pod UID if present (pattern: pod<UUID>)
		if strings.Contains(line, "-pod") {
			parts := strings.Split(line, "-pod")
			if len(parts) > 1 {
				uidPart := parts[1]
				// UUIDs are typically 36 chars: e.g. 093849...
				// But k8s cgroup paths might have .slice at the end
				uid := strings.Split(uidPart, ".")[0]
				uid = strings.TrimPrefix(uid, "") // in case of extra prefixes
				podUID = uid
			}
		} else if strings.Contains(line, "/pod") {
			parts := strings.Split(line, "/pod")
			if len(parts) > 1 {
				uidPart := parts[1]
				uid := strings.Split(uidPart, "/")[0]
				uid = strings.Split(uid, ".")[0]
				podUID = uid
			}
		}

		if strings.Contains(line, "cri-containerd-") {
			parts := strings.Split(line, "cri-containerd-")
			if len(parts) > 1 {
				containerID = strings.TrimSuffix(parts[1], ".scope")
			}
		} else if strings.Contains(line, "docker-") {
			parts := strings.Split(line, "docker-")
			if len(parts) > 1 {
				containerID = strings.TrimSuffix(parts[1], ".scope")
			}
		} else if strings.Contains(line, "kubepods") {
			parts := strings.Split(line, "/")
			lastPart := parts[len(parts)-1]
			if len(lastPart) > 60 { 
				containerID = lastPart
			}
		}
		
		if containerID != "" && podUID != "" {
			return containerID, podUID, nil
		}
	}

	if containerID != "" {
		return containerID, podUID, nil
	}

	return "", "", fmt.Errorf("identifiers not found in %s", path)
}

func (m *PodMapper) getPodByIdentifiers(containerID, podUID string) (*PodInfo, error) {
	m.cacheLock.RLock()
	// Use containerID as cache key, as it's more specific
	entry, ok := m.cache[containerID]
	m.cacheLock.RUnlock()

	if ok && time.Now().Before(entry.expiresAt) {
		return entry.info, nil
	}

	// Cache miss or expired, query K8s API
	pod, err := m.queryK8s(containerID, podUID)
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

func (m *PodMapper) queryK8s(containerID, podUID string) (*corev1.Pod, error) {
	// 1. Try UID lookup first (highly reliable)
	if podUID != "" {
		// Pod UIDs in cgroups sometimes have underscores instead of dashes
		sanitizedUID := strings.ReplaceAll(podUID, "_", "-")
		
		pod, err := m.client.CoreV1().Pods("").List(context.Background(), metav1.ListOptions{
			FieldSelector: fmt.Sprintf("spec.nodeName=%s", m.nodeName),
		})
		if err == nil {
			for _, p := range pod.Items {
				if string(p.UID) == sanitizedUID || strings.ReplaceAll(string(p.UID), "-", "") == strings.ReplaceAll(sanitizedUID, "-", "") {
					log.Printf("[DEBUG] Found match by Pod UID: %s", p.Name)
					return &p, nil
				}
			}
		}
	}

	// 2. Fallback to container ID scan
	if containerID != "" {
		pods, err := m.client.CoreV1().Pods("").List(context.Background(), metav1.ListOptions{
			FieldSelector: fmt.Sprintf("spec.nodeName=%s", m.nodeName),
		})
		if err != nil {
			return nil, err
		}

		for _, pod := range pods.Items {
			// Check application containers
			for _, status := range pod.Status.ContainerStatuses {
				if strings.Contains(status.ContainerID, containerID) {
					log.Printf("[DEBUG] Found match by Container ID: %s", pod.Name)
					return &pod, nil
				}
			}
			// Check init containers
			for _, status := range pod.Status.InitContainerStatuses {
				if strings.Contains(status.ContainerID, containerID) {
					log.Printf("[DEBUG] Found match by Init Container ID: %s", pod.Name)
					return &pod, nil
				}
			}
		}
	}

	return nil, fmt.Errorf("pod not found for Identifier (CID: %s, UID: %s) on node %s", containerID, podUID, m.nodeName)
}
