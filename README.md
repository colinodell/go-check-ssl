# go-check-ssl

Simple command line utility to check the status of an SSL certificate.

Basically, it attempts to establish a TLS connection to a server and reports back useful info about the cert's status.

## Installation

To install the utility, please [download the appropriate release](https://github.com/colinodell/go-check-ssl/releases), unarchive the files, and move the binary somewhere under your path.
To upgrade, download the latest version and replace the binary with the new one.

On macOS, you can use homebrew: `brew install colinodell/tap/check-ssl`

## Usage

To check a certificate, simply run:

```bash
check-ssl [server]
```

![](screenshot.png)

Example of allowed arguments include:

 - `example.com`
 - `example.com:443`
 - `https://www.example.com:443/foo/bar`
 - `93.184.216.34`

By default, it'll resolve the IP of the given domain and test against that server.  But you can also use this tool to check other servers by providing two arguments: the server to test and the SNI to use.  For example:

```bash
check-ssl [server] --sni=[SNI domain]

check-ssl example.com --sni=foo.example.com
```
