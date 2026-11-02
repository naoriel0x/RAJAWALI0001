package lure

import (
	"fmt"
	"math/rand"
)

type NetworkHost struct {
	IP       string
	Hostname string
	Role     string
	OS       string
	Ports    []int
}

type NetworkMapFaker struct{}

func NewNetworkMapFaker() *NetworkMapFaker {
	return &NetworkMapFaker{}
}

func (nmf *NetworkMapFaker) GenerateFakeTopology() []NetworkHost {
	return []NetworkHost{
		{
			IP:       "10.0.0.1",
			Hostname: "gateway.internal.corp",
			Role:     "Firewall / Gateway",
			OS:       "Cisco ASA 9.16",
			Ports:    []int{22, 443, 8443},
		},
		{
			IP:       "10.0.1.5",
			Hostname: "db-primary.internal.corp",
			Role:     "PostgreSQL Primary",
			OS:       "Ubuntu 22.04 LTS",
			Ports:    []int{22, 5432},
		},
		{
			IP:       "10.0.1.6",
			Hostname: "db-replica.internal.corp",
			Role:     "PostgreSQL Replica",
			OS:       "Ubuntu 22.04 LTS",
			Ports:    []int{22, 5432},
		},
		{
			IP:       "10.0.1.8",
			Hostname: "cache.internal.corp",
			Role:     "Redis Cluster",
			OS:       "Ubuntu 20.04 LTS",
			Ports:    []int{22, 6379},
		},
		{
			IP:       "10.0.1.10",
			Hostname: "app-server-01.internal.corp",
			Role:     "Application Server",
			OS:       "Ubuntu 22.04 LTS",
			Ports:    []int{22, 80, 443, 8000},
		},
		{
			IP:       "10.0.1.20",
			Hostname: "backup.internal.corp",
			Role:     "Backup Server",
			OS:       "Debian 11 Bullseye",
			Ports:    []int{22, 873},
		},
	}
}

func (nmf *NetworkMapFaker) GenerateAsText() string {
	hosts := nmf.GenerateFakeTopology()
	result := "# Network Topology Map - INTERNAL USE ONLY\n\n"
	for _, h := range hosts {
		result += fmt.Sprintf("%-15s  %-40s  %s\n", h.IP, h.Hostname, h.Role)
	}
	return result
}

func (nmf *NetworkMapFaker) GenerateAsJSON() string {
	hosts := nmf.GenerateFakeTopology()
	result := `{"network":"10.0.0.0/8","hosts":[`
	for i, h := range hosts {
		if i > 0 {
			result += ","
		}
		ports := ""
		for j, p := range h.Ports {
			if j > 0 {
				ports += ","
			}
			ports += fmt.Sprintf("%d", p)
		}
		result += fmt.Sprintf(
			`{"ip":"%s","hostname":"%s","role":"%s","os":"%s","open_ports":[%s]}`,
			h.IP, h.Hostname, h.Role, h.OS, ports,
		)
	}
	result += `]}`
	return result
}

func (nmf *NetworkMapFaker) GenerateFakeSubnet() string {
	base := rand.Intn(254) + 1
	return fmt.Sprintf("10.%d.0.0/24", base)
}