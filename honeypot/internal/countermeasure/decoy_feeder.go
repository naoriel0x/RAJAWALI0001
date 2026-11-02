package countermeasure

import (
	"fmt"
	"math/rand"

	"github.com/rs/zerolog/log"
)

type DecoyData struct {
	Type    string
	Content string
}

var fakeCredentials = []DecoyData{
	{Type: "ssh_key", Content: "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA2a2rwplBQLzHPZe5TNJCR7UXCKYmz5I/fake/key/data\n-----END RSA PRIVATE KEY-----"},
	{Type: "db_creds", Content: `{"host":"10.0.1.5","user":"db_admin","password":"Pr0duct10n@2024","db":"main_prod"}`},
	{Type: "api_key", Content: `{"service":"internal-api","key":"sk-prod-xK9mN2pL8qR4vY7wZ1aB3cD5eF6gH0iJ","expires":"2025-12-31"}`},
	{Type: "vpn_config", Content: `[Interface]\nPrivateKey = fake_private_key_here\nAddress = 10.8.0.2/24\n[Peer]\nPublicKey = fake_public_key\nEndpoint = vpn.internal.corp:51820`},
}

var fakeNetworkData = []DecoyData{
	{Type: "network_map", Content: `{"subnet":"10.0.0.0/8","hosts":["10.0.1.1 (router)","10.0.1.5 (db-server)","10.0.1.10 (app-server)","10.0.1.20 (backup)"]}`},
	{Type: "dns_zones", Content: `internal.corp -> 10.0.1.1\ndb.internal.corp -> 10.0.1.5\nbackup.internal.corp -> 10.0.1.20`},
}

type DecoyFeeder struct {
	fed map[string]int
}

func NewDecoyFeeder() *DecoyFeeder {
	return &DecoyFeeder{
		fed: make(map[string]int),
	}
}

func (df *DecoyFeeder) GetDecoy(ip, requestType string) string {
	df.fed[ip]++
	count := df.fed[ip]

	log.Info().
		Str("ip", ip).
		Str("type", requestType).
		Int("feed_count", count).
		Msg("Decoy intel fed to attacker")

	switch requestType {
	case "credentials":
		idx := rand.Intn(len(fakeCredentials))
		return fakeCredentials[idx].Content
	case "network":
		idx := rand.Intn(len(fakeNetworkData))
		return fakeNetworkData[idx].Content
	default:
		return fmt.Sprintf(`{"data":"restricted","ref":"doc-%d","classification":"internal"}`, rand.Intn(9999))
	}
}

func (df *DecoyFeeder) GetFeedCount(ip string) int {
	return df.fed[ip]
}