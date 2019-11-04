package main

import (
	"crypto/tls"
	"fmt"
	"os"
)

/*
printConnectionDetails prints important TLS connection details
*/
func printConnectionDetails(conn *tls.Conn) {

	state := conn.ConnectionState()

	fmt.Printf("\nTLS CONNECTION DETAILS ...\n")
	fmt.Printf(leftValue+"%d (%#04x, %s)\n", "Version", state.Version, state.Version, getTLSVersion(state.Version))
	fmt.Printf(leftValue+"%t\n", "HandshakeComplete", state.HandshakeComplete)
	fmt.Printf(leftValue+"%d (%#04x, %s)\n", "CipherSuite", state.CipherSuite, state.CipherSuite, getCipherSuite(state.CipherSuite))

	if debug {
		printDump("connection state", state)
	}

	localAddr := conn.LocalAddr()
	localHost, _ := os.Hostname()
	remoteAddr := conn.RemoteAddr()
	fmt.Printf("\nNETWORK ADDRESS DETAILS ...\n")
	fmt.Printf(leftValue+"%s\n", "LocalAddr", localAddr.String())
	fmt.Printf(leftValue+"%s\n", "LocalHost", localHost)
	fmt.Printf(leftValue+"%s\n", "RemoteAddr", remoteAddr.String())
}

/*
getTLSVersion gets the TLS version literal
*/
func getTLSVersion(version uint16) string {

	switch version {
	case tls.VersionSSL30:
		return "VersionSSL30"
	case tls.VersionTLS10:
		return "VersionTLS10"
	case tls.VersionTLS11:
		return "VersionTLS11"
	case tls.VersionTLS12:
		return "VersionTLS12"
	case tls.VersionTLS13:
		return "VersionTLS13"
	default:
		return "UNKNOWN"
	}
}

/*
getCipherSuite gets the Cipher Suite literal
*/
func getCipherSuite(cipherSuite uint16) string {

	switch cipherSuite {
	// TLS 1.0 - 1.2 cipher suites
	case tls.TLS_RSA_WITH_RC4_128_SHA:
		return "TLS_RSA_WITH_RC4_128_SHA"
	case tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:
		return "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
	case tls.TLS_RSA_WITH_AES_128_CBC_SHA:
		return "TLS_RSA_WITH_AES_128_CBC_SHA"
	case tls.TLS_RSA_WITH_AES_256_CBC_SHA:
		return "TLS_RSA_WITH_AES_256_CBC_SHA"
	case tls.TLS_RSA_WITH_AES_128_CBC_SHA256:
		return "TLS_RSA_WITH_AES_128_CBC_SHA256"
	case tls.TLS_RSA_WITH_AES_128_GCM_SHA256:
		return "TLS_RSA_WITH_AES_128_GCM_SHA256"
	case tls.TLS_RSA_WITH_AES_256_GCM_SHA384:
		return "TLS_RSA_WITH_AES_256_GCM_SHA384"
	case tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:
		return "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
		return "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
		return "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"
	case tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA:
		return "TLS_ECDHE_RSA_WITH_RC4_128_SHA"
	case tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:
		return "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"
	case tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
		return "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"
	case tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
		return "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
		return "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"
	case tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
		return "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
	case tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
		return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
		return "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
	case tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
		return "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
		return "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
	case tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305:
		return "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305"
	case tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305:
		return "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305"
	// TLS 1.3 cipher suites
	case tls.TLS_AES_128_GCM_SHA256:
		return "TLS_AES_128_GCM_SHA256"
	case tls.TLS_AES_256_GCM_SHA384:
		return "TLS_AES_256_GCM_SHA384"
	case tls.TLS_CHACHA20_POLY1305_SHA256:
		return "TLS_CHACHA20_POLY1305_SHA256"
	// TLS_FALLBACK_SCSV isn't a standard cipher suite but an indicator that the client is doing version fallback. See RFC 7507.
	case tls.TLS_FALLBACK_SCSV:
		return "TLS_FALLBACK_SCSV"
	default:
		return "UNKNOWN"
	}
}
