package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"os"
	"reflect"
	"strings"

	"github.com/dustin/go-humanize"
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

	input := os.Args[1]
	if !strings.Contains(input, "://") {
		input = "https://" + input
	}

	parsedUrl, err := url.Parse(input)
	if err != nil {
		fmt.Printf("Invalid URL: %s\n", err)
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

	fmt.Printf("Connecting to %s as %s...\n\n", server, hostname)

	var valid bool
	if err := checkIfCertValid(server, hostname); err != nil {
		valid = false
		fmt.Printf("ERROR: %s\n\n", err)
	} else {
		valid = true
		fmt.Printf("Cert seems to be valid\n\n")
	}

	cert, err := getCert(server, hostname)
	if err != nil {
		fmt.Printf("ERROR: %s\n", err)
		os.Exit(1)
	}

	fmt.Printf("Issued by:  %s\n", split(cert.Issuer, 12))

	fmt.Printf("Subject:    %s\n", cert.Subject)
	fmt.Printf("DNS Names:  %s\n", split(cert.DNSNames, 12))

	fmt.Printf("Expires:    %s (%s)\n", humanize.Time(cert.NotAfter), cert.NotAfter.String())

	if !valid {
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

func split(value interface{}, padding int) string {
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
