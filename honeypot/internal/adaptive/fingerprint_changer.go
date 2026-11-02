package adaptive

import (
	"math/rand"

	"github.com/rs/zerolog/log"
)

var sshBanners = []string{
	"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
	"SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7",
	"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.11",
	"SSH-2.0-OpenSSH_9.0p1 Ubuntu-1ubuntu8.5",
}

var serverHeaders = []string{
	"Apache/2.4.52 (Ubuntu)",
	"nginx/1.18.0 (Ubuntu)",
	"Apache/2.4.41 (Debian)",
	"nginx/1.24.0",
}

var poweredBy = []string{
	"PHP/8.1.2",
	"PHP/7.4.33",
	"PHP/8.2.1",
	"",
}

type FingerprintChanger struct {
	currentSSHBanner string
	currentServer    string
	currentPoweredBy string
}

func NewFingerprintChanger() *FingerprintChanger {
	fc := &FingerprintChanger{}
	fc.Rotate()
	return fc
}

func (fc *FingerprintChanger) Rotate() {
	fc.currentSSHBanner = sshBanners[rand.Intn(len(sshBanners))]
	fc.currentServer = serverHeaders[rand.Intn(len(serverHeaders))]
	fc.currentPoweredBy = poweredBy[rand.Intn(len(poweredBy))]

	log.Info().
		Str("ssh_banner", fc.currentSSHBanner).
		Str("server_header", fc.currentServer).
		Msg("Honeypot fingerprint rotated")
}

func (fc *FingerprintChanger) GetSSHBanner() string {
	return fc.currentSSHBanner
}

func (fc *FingerprintChanger) GetServerHeader() string {
	return fc.currentServer
}

func (fc *FingerprintChanger) GetPoweredBy() string {
	return fc.currentPoweredBy
}