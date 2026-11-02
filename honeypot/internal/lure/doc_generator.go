package lure

import (
	"fmt"
	"time"
)

type FakeDocument struct {
	Title    string
	Content  string
	Filename string
	MimeType string
}

type DocGenerator struct{}

func NewDocGenerator() *DocGenerator {
	return &DocGenerator{}
}

func (dg *DocGenerator) GenerateConfigFile() FakeDocument {
	content := fmt.Sprintf(`# Production Configuration
# Generated: %s
# WARNING: Keep this file secure

[database]
host     = 10.0.1.5
port     = 5432
name     = production_db
user     = prod_user
password = Pr0d@2024!Secure

[redis]
host     = 10.0.1.8
port     = 6379
password = R3d1s$ecret#2024

[api]
secret_key = sk-prod-xK9mN2pL8qR4vY7wZ1aB3cD5eF6gH0iJ
jwt_secret = jwt-prod-secret-key-2024

[smtp]
host     = smtp.internal.corp
user     = noreply@company.com
password = Smtp@Internal2024
`, time.Now().Format("2006-01-02"))

	return FakeDocument{
		Title:    "Production Config",
		Content:  content,
		Filename: "config.prod.ini",
		MimeType: "text/plain",
	}
}

func (dg *DocGenerator) GenerateEnvFile() FakeDocument {
	content := `# Environment Variables - PRODUCTION
DB_HOST=10.0.1.5
DB_PORT=5432
DB_USER=prod_admin
DB_PASS=Sup3rSecr3t!Prod
DB_NAME=main_production

REDIS_HOST=10.0.1.8
REDIS_PASS=R3d!sPwd2024

AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
AWS_REGION=ap-southeast-1

JWT_SECRET=super-secret-jwt-key-production-2024
API_KEY=prod-api-key-xK9mN2pL8qR4vY7wZ`

	return FakeDocument{
		Title:    "Environment File",
		Content:  content,
		Filename: ".env.production",
		MimeType: "text/plain",
	}
}

func (dg *DocGenerator) GenerateNetworkMap() FakeDocument {
	content := `# Internal Network Map - CONFIDENTIAL
# Last updated: 2024-11-01

10.0.0.1    gateway.internal.corp       (Cisco ASA Firewall)
10.0.1.1    core-switch.internal.corp   (Cisco Catalyst 9300)
10.0.1.5    db-primary.internal.corp    (PostgreSQL Primary)
10.0.1.6    db-replica.internal.corp    (PostgreSQL Replica)
10.0.1.8    cache.internal.corp         (Redis Cluster)
10.0.1.10   app-server-01.internal.corp (Application Server)
10.0.1.11   app-server-02.internal.corp (Application Server)
10.0.1.20   backup.internal.corp        (Backup Server)
10.0.1.50   monitoring.internal.corp    (Prometheus + Grafana)
10.0.2.1    vpn.internal.corp           (WireGuard VPN)`

	return FakeDocument{
		Title:    "Network Map",
		Content:  content,
		Filename: "network_map.txt",
		MimeType: "text/plain",
	}
}

func (dg *DocGenerator) GetByPath(path string) *FakeDocument {
	switch path {
	case "/backup/config":
		doc := dg.GenerateConfigFile()
		return &doc
	case "/backup/env":
		doc := dg.GenerateEnvFile()
		return &doc
	case "/backup/network":
		doc := dg.GenerateNetworkMap()
		return &doc
	default:
		return nil
	}
}