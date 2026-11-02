package lure

import (
	"fmt"
	"math/rand"
)

var usernames = []string{"admin", "root", "deploy", "backup", "sysadmin", "devops", "app"}
var domains = []string{"internal.corp", "prod.local", "company.internal"}

type CredentialFaker struct{}

func NewCredentialFaker() *CredentialFaker {
	return &CredentialFaker{}
}

func (cf *CredentialFaker) GenerateFakeCredentials(count int) []map[string]string {
	creds := make([]map[string]string, 0, count)
	for i := 0; i < count; i++ {
		user := usernames[rand.Intn(len(usernames))]
		domain := domains[rand.Intn(len(domains))]
		creds = append(creds, map[string]string{
			"username": fmt.Sprintf("%s@%s", user, domain),
			"password": fmt.Sprintf("$2y$10$%s", generateFakeHash()),
			"role":     randomRole(),
		})
	}
	return creds
}

func (cf *CredentialFaker) GenerateFakeSSHKey() string {
	return "-----BEGIN RSA PRIVATE KEY-----\n" +
		"MIIEowIBAAKCAQEA2a2rwplBQLzHPZe5TNJCR7UXCKYmz5I/\n" +
		"[FAKE KEY DATA - HONEYPOT]\n" +
		"-----END RSA PRIVATE KEY-----"
}

func generateFakeHash() string {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 40)
	for i := range b {
		b[i] = chars[rand.Intn(len(chars))]
	}
	return string(b)
}

func randomRole() string {
	roles := []string{"admin", "operator", "readonly", "superuser"}
	return roles[rand.Intn(len(roles))]
}