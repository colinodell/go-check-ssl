package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/revoke"
	"github.com/dustin/go-humanize"
	"net"
	"net/url"
	"os"
	"reflect"
	"strings"

	. "github.com/logrusorgru/aurora"
)

func main() {
	if len(os.Args) < 2 || len(os.Args) > 3 {
		fmt.Print("go-check-ssl: Simple command line utility to check the status of an SSL certificate.\n\n")
		fmt.Printf("Usage: %s server [domain]\n", os.Args[0])
		fmt.Println()
		fmt.Print("Arguments:\n")
		fmt.Print("  - 'server' should be any valid hostname, IP, or URL to test\n")
		fmt.Print("  - '[domain]' allows you to provide an arbitrary domain name to use for SNI\n")
		fmt.Println()
		fmt.Print("Example usage:\n")
		fmt.Printf("  - %s example.com\n", os.Args[0])
		fmt.Printf("  - %s https://www.example.com:443/foo/bar\n", os.Args[0])
		fmt.Printf("  - %s 93.184.216.34 www.example.com\n", os.Args[0])
		fmt.Printf("  - %s 93.184.216.34:443 www.example.com\n", os.Args[0])
		os.Exit(1)
	}

	log.SetLogger(new(logger))

	input := os.Args[1]
	if !strings.Contains(input, "://") {
		input = "https://" + input
	}

	parsedUrl, err := url.Parse(input)
	if err != nil {
		fmt.Println(Red("Invalid URL: " + err.Error()))
		os.Exit(1)
	}

	// Hostname is used for SNI
	hostname := parsedUrl.Hostname()
	// Server is used for the underlying connection
	server := hostname
	port := parsedUrl.Port()
	if port == "" {
		port = "443"
	}

	// Did the user provide a different hostname to use for SNI?
	if len(os.Args) > 2 {
		hostname = os.Args[2]
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

	if ! ok {
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
		ServerName: hostname,
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
