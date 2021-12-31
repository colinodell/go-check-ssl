package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/revoke"
	"github.com/dustin/go-humanize"
	"gopkg.in/alecthomas/kingpin.v2"
	"net"
	"net/url"
	"os"
	"reflect"
	"strings"

	. "github.com/logrusorgru/aurora"
)

var (
	server  = kingpin.Arg("host", "Hostname, IP, or URL of the server to check.").String()
	sni     = kingpin.Flag("sni", "SNI server to use for the certificate (optional).").Short('s').String()
)

func main() {
	log.SetLogger(new(logger))

	kingpin.Parse()
	if server == nil || *server == "" {
		kingpin.Usage()
		os.Exit(1)
	}

	input := *server
	if !strings.Contains(input, "://") {
		input = "https://" + input
	}

	parsedUrl, err := url.Parse(input)
	if err != nil {
		fmt.Println(Red("Invalid URL: " + err.Error()))
		os.Exit(1)
	}

	// Hostname is used for SNI by default
	hostname := parsedUrl.Hostname()
	// Server is used for the underlying connection
	server := hostname
	port := parsedUrl.Port()
	if port == "" {
		port = "443"
	}

	// Did the user provide a different server to use for SNI?
	if sni != nil && *sni != "" {
		hostname = *sni
	}

	// Resolve the IP of the server
	if addr, err := net.LookupIP(server); err == nil {
		server = addr[0].String()
	}

	server += ":" + port

	fmt.Printf("Connecting to %s as %s...\n", server, hostname)

	valid := true

	if err := checkIfCertValid(server, hostname); err != nil {
		valid = false
		log.Warningf("Failed to verify cert by connecting to the server: %s", err)
	} else {
		fmt.Println(Green("Successfully connected to server"))
	}

	fmt.Println("")

	cert, err := getCert(server, hostname)
	if err != nil {
		log.Errorf("Failed to load the cert by connecting to the server: %s", err)
		os.Exit(1)
	}

	fmt.Printf("Issued by:  %s\n", splitLines(cert.Issuer, 12))
	fmt.Printf("Issued:     %s (%s)\n", cert.NotBefore.String(), humanize.Time(cert.NotBefore))
	fmt.Printf("Expires:    %s (%s)\n", cert.NotAfter.String(), humanize.Time(cert.NotAfter))

	fmt.Printf("Subject:    %s\n", cert.Subject)
	fmt.Printf("DNS Names:  %s\n", splitLines(cert.DNSNames, 12))

	fmt.Println()

	revoked, ok, err := revoke.VerifyCertificateError(cert)

	if revoked {
		valid = false
	}

	if !ok {
		valid = false
		log.Warning("Failed to verify certificate revocation status")
	}

	if err != nil {
		valid = false
		log.Warningf("Failed to verify certificate revocation status: %s", err)
	}

	if valid {
		fmt.Println(Green("Certificate seems to be valid"))
		os.Exit(0)
	} else {
		fmt.Println(Red("Certificate is invalid"))
		os.Exit(1)
	}
}

func checkIfCertValid(server, hostname string) error {
	conf := &tls.Config{
		ServerName: hostname,
	}

	conn, err := tls.Dial("tcp", server, conf)
	if err != nil {
		return err
	}

	conn.Close()

	return nil
}

func getCert(server, hostname string) (*x509.Certificate, error) {
	conf := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         hostname,
	}

	conn, err := tls.Dial("tcp", server, conf)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	return conn.ConnectionState().PeerCertificates[0], nil
}

func splitLines(value interface{}, padding int) string {
	var lines []string

	if reflect.TypeOf(value).Kind() == reflect.Slice {
		s := reflect.ValueOf(value)
		for i := 0; i < s.Len(); i++ {
			lines = append(lines, fmt.Sprintf("%v", s.Index(i)))
		}
	} else {
		v := fmt.Sprintf("%v", value)
		for _, line := range strings.Split(v, "\n") {
			lines = append(lines, line)
		}
	}

	if len(lines) == 0 {
		return ""
	}

	var sb strings.Builder

	// No padding for the first line
	sb.WriteString(fmt.Sprintf("%v", lines[0]))

	for _, s := range lines[1:] {
		sb.WriteString("\n")
		sb.WriteString(strings.Repeat(" ", padding))
		sb.WriteString(fmt.Sprintf("%v", s))
	}

	return sb.String()
}
