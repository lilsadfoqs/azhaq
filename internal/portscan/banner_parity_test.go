package portscan

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

// Recorded greetings, one per product, each with what `nmap -sV` printed for
// the same bytes served from a stand-in (its service, product and version).
// The service, product and version azhaq reads must say the same thing: the
// product starts with the same word as the nmap label ("Postfix" and
// "Postfix smtpd"; nmap adds the daemon's role, azhaq keeps the name its
// advisories and docs use), and the version is the nmap version up to the first space (nmap appends the
// distribution; azhaq keeps it in extrainfo).
func TestGreetingsParseLikeTheReference(t *testing.T) {
	tests := []struct {
		raw                           string
		service                       string // "" when the greeting does not say one by itself
		nmapProduct, nmapVersion, why string
	}{
		{"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10\r\n", "ssh", "OpenSSH", "8.9p1 Ubuntu 3ubuntu0.10", "ssh"},
		{"SSH-2.0-OpenSSH_for_Windows_8.1\r\n", "ssh", "OpenSSH", "for_Windows_8.1", "ssh windows"},
		{"SSH-2.0-dropbear_2020.81\r\n", "ssh", "Dropbear sshd", "2020.81", "ssh"},
		{"SSH-1.99-Cisco-1.25\r\n", "ssh", "Cisco SSH", "1.25", "ssh"},
		{"SSH-2.0-ROSSSH\r\n", "ssh", "MikroTik RouterOS sshd", "", "ssh"},
		{"SSH-2.0-Sun_SSH_1.1.8\r\n", "ssh", "SunSSH", "1.1.8", "ssh"},
		{"SSH-2.0-mod_sftp\r\n", "ssh", "ProFTPD mod_sftp", "", "ssh"},
		{"SSH-2.0-Serv-U_15.2.3.742\r\n", "ssh", "Serv-U SSH Server", "15.2.3.742", "ssh"},
		{"SSH-2.0-9.99 FlowSsh: Bitvise SSH Server (WinSSHD) 8.49: free only for personal non-commercial use\r\n", "ssh", "Bitvise WinSSHD", "8.49", "ssh"},
		{"220 (vsFTPd 3.0.3)\r\n", "", "vsftpd", "3.0.3", "ftp"},
		{"220 ProFTPD 1.3.5e Server (ProFTPD Default Installation) [127.0.0.1]\r\n", "", "ProFTPD", "1.3.5e", "ftp"},
		{"220 ProFTPD Server (Debian) [::ffff:127.0.0.1]\r\n", "", "ProFTPD", "", "ftp"},
		{"220-Welcome to Pure-FTPd\r\n220-You are user number 1 of 50 allowed\r\n", "", "Pure-FTPd", "", "ftp"},
		{"220 Serv-U FTP Server v15.1 ready...\r\n", "", "Serv-U ftpd", "15.1", "ftp"},
		{"220 FileZilla Server version 0.9.60 beta\r\n", "", "FileZilla ftpd", "0.9.60 beta", "ftp"},
		{"220 mypc NcFTPd Server (licensed copy) ready.\r\n", "", "NcFTPd", "", "ftp"},
		{"220 Gene6 FTP Server v3.10.0 (Build 2) ready...\r\n", "", "Gene6 ftpd", "3.10.0 build 2", "ftp"},
		{"220 MikroTik FTP server (MikroTik 6.48.6) ready\r\n", "", "MikroTik router ftpd", "6.48.6", "ftp"},
		{"220 Titan FTP Server 10.47.1892 Ready.\r\n", "", "Titan ftpd", "10.47.1892", "ftp"},
		{"220 ftp.example.com FTP server (GNU inetutils 1.9.4) ready.\r\n", "", "GNU Inetutils FTPd", "1.9.4", "ftp"},
		{"220 Bftpd 1.6.5 at 127.0.0.1 ready\r\n", "", "Bftpd", "1.6.5", "ftp"},
		{"220 Microsoft FTP Service\r\n", "", "Microsoft ftpd", "", "ftp"},
		{"220 mail.example.com ESMTP Postfix (Ubuntu)\r\n", "", "Postfix smtpd", "", "smtp"},
		{"220 mx.example.com ESMTP Exim 4.96 Tue, 28 Oct 2026 10:00:00 +0000\r\n", "", "Exim smtpd", "4.96", "smtp"},
		{"220 host.example.com ESMTP Sendmail 8.15.2/8.15.2; Tue, 28 Oct 2026 10:00:00 GMT\r\n", "", "Sendmail", "8.15.2", "smtp"},
		{"220 mail ESMTP Haraka 3.0.0 ready\r\n", "", "Haraka smtpd", "3.0.0", "smtp"},
		{"220 mail.example.com Microsoft ESMTP MAIL Service, Version: 10.0.17763.1 ready at Tue, 3 Nov 2026\r\n", "", "Microsoft", "10.0.17763.1", "smtp"},
		{"220 mx.example.com ESMTP MDaemon 21.5.1; Tue, 3 Nov 2026 10:00:00 +0000\r\n", "", "MDaemon smtpd", "21.5.1", "smtp"},
		{"220 mx.google.com ESMTP abc123 - gsmtp\r\n", "", "Google gsmtp", "", "smtp"},
		{"+OK Dovecot ready.\r\n", "", "Dovecot pop3d", "", "pop3"},
		{"* OK [CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE LITERAL+ STARTTLS AUTH=PLAIN] Dovecot (Ubuntu) ready.\r\n", "", "Dovecot imapd", "", "imap"},
		{"+OK Microsoft Exchange Server 2016 POP3 server version 15.01.2308.008 (mail.example.com) ready.\r\n", "", "Microsoft Exchange", "15.01.2308.008", "pop3"},
		{"* OK The Microsoft Exchange IMAP4 service is ready.\r\n", "", "Microsoft Exchange", "", "imap"},
	}
	for _, tt := range tests {
		service, product, version := greetingProduct([]byte(tt.raw), printable([]byte(tt.raw)))
		if tt.service != "" && service != tt.service {
			t.Errorf("%q: service %q, want %q", tt.raw, service, tt.service)
		}
		a, _, _ := strings.Cut(strings.ToLower(product), " ")
		b, _, _ := strings.Cut(strings.ToLower(tt.nmapProduct), " ")
		if product == "" || a != b {
			t.Errorf("%q: product %q, nmap says %q", tt.raw, product, tt.nmapProduct)
		}
		first, _, _ := strings.Cut(tt.nmapVersion, " ")
		if tt.nmapVersion == "for_Windows_8.1" {
			first = "8.1" // nmap keeps the "for_Windows_" the line carries; the version is what follows
		}
		if strings.ToLower(version) != strings.ToLower(first) {
			t.Errorf("%q: version %q, nmap says %q", tt.raw, version, tt.nmapVersion)
		}
	}
}

// A server that looks the client up before it greets, as sshd does with
// UseDNS, may be slower than the connect wait. nmap listens for six seconds
// on a plain connect; so does the second look, on a port that has a service
// of its own and on one that has not.
func TestSlowSSHGreetingIsReadLikeTheReference(t *testing.T) {
	t.Parallel()
	greet := func(c net.Conn) {
		time.Sleep(5 * time.Second)
		_, _ = c.Write([]byte("SSH-2.0-OpenSSH_7.4\r\n"))
		time.Sleep(300 * time.Millisecond)
	}
	first, other := listen(t, greet), listen(t, greet)
	saved := speaksFirst
	t.Cleanup(func() { speaksFirst = saved })
	speaksFirst = func(p int) bool { return p == first }
	s := &Scanner{}
	r, err := s.ScanEach(context.Background(), "localhost", "127.0.0.1", []int{first, other})
	if err != nil || len(r.Open) != 2 {
		t.Fatalf("scan: %v %+v", err, r)
	}
	for _, o := range r.Open {
		if o.Service != "ssh" || o.Product != "OpenSSH" || o.Version != "7.4" {
			t.Errorf("port %d (%q): %q %q %q, want ssh OpenSSH 7.4", o.Port, o.Banner, o.Service, o.Product, o.Version)
		}
	}
}
