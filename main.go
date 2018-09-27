/*
Purpose:
- monitor public key certificate

Description:
- Prints public key certificate details offered by TLS service.

Releases:
- 0.1.0 - 2018/09/23 : initial release
- 0.2.0 - 2018/09/24 : output format modified, verbose mode implemented
- 0.3.0 - 2018/09/25 : added: time calculations, ExtKeyUsage, fingerprints
- 0.4.0 - 2018/09/26 : added: SubjectKeyId, AuthorityKeyId, debug option, connection details, network details
- 0.5.0 - 2018/09/27 : added: PolicyIdentifiers
- 0.5.1 - 2018/09/27 : small corrections

Author:
- Klaus Tockloth

Copyright and license:
- Copyright (c) 2018 Klaus Tockloth
- MIT license

Permission is hereby granted, free of charge, to any person obtaining a copy of this software
and associated documentation files (the Software), to deal in the Software without restriction,
including without limitation the rights to use, copy, modify, merge, publish, distribute,
sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or
substantial portions of the Software.

The software is provided 'as is', without warranty of any kind, express or implied, including
but not limited to the warranties of merchantability, fitness for a particular purpose and
noninfringement. In no event shall the authors or copyright holders be liable for any claim,
damages or other liability, whether in an action of contract, tort or otherwise, arising from,
out of or in connection with the software or the use or other dealings in the software.

Contact (eMail):
- freizeitkarte@googlemail.com

Remarks:
- Possible improvements (nice-to-have):
  - Find issuer certificate by using "AuthorityKeyId" instead of "Issuer-CN".
  - Load missing issuer certificate if the leaf certificate has "IssuingCertificateURL".
  - Implement support for certificate revocation lists (CRLs).
  - Show textual meaning of "PolicyIdentifiers" (eg. DV, OV, EV).
  - Print operating system hostname for local address.
  - Print DNS details (records) for remote address.

Links:
- https://godoc.org/golang.org/x/crypto/ocsp
*/

package main

import (
	"bytes"
	"crypto"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/davecgh/go-spew/spew"
	"golang.org/x/crypto/ocsp"
)

// general program info
var (
	progName    = os.Args[0]
	progVersion = "0.5.1"
	progDate    = "2018/09/27"
	progPurpose = "monitor public key certificate"
	progInfo    = "Prints public key certificate details offered by TLS service."
)

// global objects / command line settings
var timeout *int
var verbose *bool
var debug *bool
var start time.Time

/*
main starts this program
*/
func main() {

	timeout = flag.Int("timeout", 19, "communication timeout in seconds")
	verbose = flag.Bool("verbose", false, "adds fingerprints, PEM certificate, PEM OCSP response")
	debug = flag.Bool("debug", false, "prints internal representation of connection, certificate, OCSP response")

	flag.Usage = printUsage
	flag.Parse()

	// at least one argument required
	if len(flag.Args()) == 0 {
		fmt.Printf("\nError:\n  address:port argument (TLS service) required.\n")
		printUsage()
	}

	// check timeout setting
	if *timeout < 1 {
		fmt.Printf("\nError:\n  Invalid setting <%v> for -timeout option.\n", *timeout)
		printUsage()
	}

	service := flag.Args()[0]
	start = time.Now()

	fmt.Printf("GENERAL INFORMATION ...\n")
	fmt.Printf("Service : %s\n", service)
	fmt.Printf("Timeout : %d\n", *timeout)
	fmt.Printf("Verbose : %t\n", *verbose)
	fmt.Printf("Debug   : %t\n", *debug)
	fmt.Printf("Time    : %s\n", start.Format("2006-01-02 15:04:05 -0700 MST"))

	// connect to service
	config := &tls.Config{
		InsecureSkipVerify: true,
	}
	dialer := &net.Dialer{
		Timeout: time.Duration(*timeout) * time.Second,
	}
	conn, err := tls.DialWithDialer(dialer, "tcp", service, config)
	if err != nil {
		fmt.Printf("Error: unable to connect to service, error = %v\n", err)
		os.Exit(1)
	}

	// print connection details
	printConnectionState(conn)

	// shut down the connection
	err = conn.Close()
	if err != nil {
		fmt.Printf("Error: unable to close connection, error = %v\n", err)
		os.Exit(1)
	}

	os.Exit(0)
}

/*
printConnectionState prints some data from the connection state
*/
func printConnectionState(conn *tls.Conn) {

	state := conn.ConnectionState()

	fmt.Printf("\nTLS CONNECTION DETAILS ...\n")
	fmt.Printf("Version           : %d (%#04x, %s)\n", state.Version, state.Version, getTLSVersion(state.Version))
	fmt.Printf("HandshakeComplete : %t\n", state.HandshakeComplete)
	fmt.Printf("CipherSuite       : %d (%#04x, %s)\n", state.CipherSuite, state.CipherSuite, getCipherSuite(state.CipherSuite))

	if *debug {
		printDump("connection state", state)
	}

	localAddr := conn.LocalAddr()
	remoteAddr := conn.RemoteAddr()
	fmt.Printf("\nNETWORK ADDRESS DETAILS ...\n")
	fmt.Printf("LocalAddr  : %s\n", localAddr.String())
	fmt.Printf("RemoteAddr : %s\n", remoteAddr.String())

	var issuerCertificate *x509.Certificate
	var issuerCommonName string

	// print some public key certificate data
	for index, certificate := range state.PeerCertificates {
		if index == 0 {
			issuerCommonName = certificate.Issuer.CommonName
		}
		if index > 0 {
			if issuerCommonName == certificate.Subject.CommonName {
				issuerCertificate = certificate
			}
		}
		fmt.Printf("\nCERTIFICATE DETAILS ...\n")
		printCertificateDetails(certificate)
	}

	// stapled OCSP response from server (if any)
	if state.OCSPResponse != nil {
		if issuerCertificate != nil {
			fmt.Printf("\nOCSP DETAILS - STAPLED INFORMATION ...\n")
			printOCSPDetails(state.OCSPResponse, issuerCertificate)
		}
	}

	// response from OCSP server (if defined)
	if len(state.PeerCertificates[0].OCSPServer) > 0 {
		if issuerCertificate != nil {
			leafCertificate := state.PeerCertificates[0]
			ocspServer := state.PeerCertificates[0].OCSPServer[0]
			rawOCSPResponse, err := fetchOCSPResponseFromService(leafCertificate, issuerCertificate, ocspServer)
			if err != nil {
				fmt.Printf("Error: unable to fetch OCSP state from service, error = %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("\nOCSP DETAILS - SERVICE RESPONSE ...\n")
			printOCSPDetails(rawOCSPResponse, issuerCertificate)
		}
	}
}

/*
printUsage prints the usage of this program
*/
func printUsage() {

	fmt.Printf("\nProgram:\n")
	fmt.Printf("  Name    : %s\n", progName)
	fmt.Printf("  Release : %s - %s\n", progVersion, progDate)
	fmt.Printf("  Purpose : %s\n", progPurpose)
	fmt.Printf("  Info    : %s\n", progInfo)

	fmt.Printf("\n" +
		"What does this tool do?\n" +
		"  - connects to a TLS service and grabs the public key certificate\n" +
		"  - if certificate contains OCSP stapling data: parses the data\n" +
		"  - if certificate contains link to OCSP service: requests the status\n" +
		"  - prints out a subset (the important part) of the collected data\n" +
		"\n" +
		"Possible return values:\n" +
		"  - 0 = OK\n" +
		"  - >0 = NOK\n" +
		"\n" +
		"How to check the validity of a public key certificate?\n" +
		"  - assess 'NotBefore' value of leaf certificate\n" +
		"  - assess 'NotAfter' value of leaf certificate\n" +
		"  - assess 'Status' value(s) of OCSP response(s)\n" +
		"\n" +
		"Possible certificate 'KeyUsage' values (binary encoded):\n" +
		"  - 000000001 = DigitalSignature\n" +
		"  - 000000010 = ContentCommitment\n" +
		"  - 000000100 = KeyEncipherment\n" +
		"  - 000001000 = DataEncipherment\n" +
		"  - 000010000 = KeyAgreement\n" +
		"  - 000100000 = CertSign\n" +
		"  - 001000000 = CRLSign\n" +
		"  - 010000000 = EncipherOnly\n" +
		"  - 100000000 = DecipherOnly\n" +
		"\n" +
		"Possible certificate 'ExtKeyUsage' values:\n" +
		"  - Any\n" +
		"  - ServerAuth\n" +
		"  - ClientAuth\n" +
		"  - CodeSigning\n" +
		"  - EmailProtection\n" +
		"  - IPSECEndSystem\n" +
		"  - IPSECTunnel\n" +
		"  - IPSECUser\n" +
		"  - TimeStamping\n" +
		"  - OCSPSigning\n" +
		"  - MicrosoftServerGatedCrypto\n" +
		"  - NetscapeServerGatedCrypto\n" +
		"  - MicrosoftCommercialCodeSigning\n" +
		"  - MicrosoftKernelCodeSigning\n" +
		"\n" +
		"Possible OCSP 'Status' values:\n" +
		"  - Good\n" +
		"  - Revoked\n" +
		"  - Unknown\n" +
		"  - ServerFailed\n" +
		"\n" +
		"Possible OCSP 'RevocationReason' values:\n" +
		"  - 0 = Unspecified\n" +
		"  - 1 = KeyCompromise\n" +
		"  - 2 = CACompromise\n" +
		"  - 3 = AffiliationChanged\n" +
		"  - 4 = Superseded\n" +
		"  - 5 = CessationOfOperation\n" +
		"  - 6 = CertificateHold\n" +
		"  - 8 = RemoveFromCRL\n" +
		"  - 9 = PrivilegeWithdrawn\n" +
		"  - 10 = AACompromise\n")

	fmt.Printf("\nUsage:\n")
	fmt.Printf("  %s [-timeout=sec] [-verbose] address:port\n", progName)

	fmt.Printf("\nExamples:\n")
	fmt.Printf("  %s example.com:443\n", progName)
	fmt.Printf("  %s -timeout=7 example.com:443\n", progName)
	fmt.Printf("  %s -verbose example.com:443\n", progName)

	fmt.Printf("\nOptions:\n")
	flag.PrintDefaults()

	fmt.Printf("\nArguments:\n")
	fmt.Printf("  address:port\n")
	fmt.Printf("        address (name/ip) and port of TLS service\n")

	fmt.Printf("\nRemarks:\n" +
		"  - The timeout setting will be used:\n" +
		"    + as connection timeout when requesting the TLS service\n" +
		"    + as overall timeout when requesting the OCSP service\n" +
		"  - empty or invalid values are not printed\n")

	fmt.Printf("\nReference output (nonverbose):\n%s\n", referenceOutput)

	os.Exit(1)
}

/*
printCertificateDetails prints important certificate details / information
*/
func printCertificateDetails(certificate *x509.Certificate) {

	if *debug {
		printDump("certificate", certificate)
	}

	// basics
	fmt.Printf("SignatureAlgorithm    : %s\n", certificate.SignatureAlgorithm)
	fmt.Printf("PublicKeyAlgorithm    : %s\n", certificate.PublicKeyAlgorithm)
	fmt.Printf("Version               : %v\n", certificate.Version)
	fmt.Printf("SerialNumber          : %s\n", certificate.SerialNumber)
	fmt.Printf("Subject               : %s\n", certificate.Subject)
	fmt.Printf("Issuer                : %s\n", certificate.Issuer)
	diff := certificate.NotAfter.Sub(certificate.NotBefore)
	fmt.Printf("NotBefore             : %s (valid for %d days)\n", certificate.NotBefore, diff/(time.Hour*24))
	diff = certificate.NotAfter.Sub(start)
	fmt.Printf("NotAfter              : %s (expires in %d days)\n", certificate.NotAfter, diff/(time.Hour*24))

	// extensions (optional)
	if certificate.KeyUsage > 0 {
		keyUsages := buildKeyUsages(certificate.KeyUsage)
		fmt.Printf("KeyUsage              : %v (%b, %s)\n", certificate.KeyUsage, certificate.KeyUsage, strings.Join(keyUsages, ", "))
	}
	if len(certificate.ExtKeyUsage) > 0 {
		extKeyUsages := buildExtKeyUsages(certificate.ExtKeyUsage)
		fmt.Printf("ExtKeyUsage           : %s\n", strings.Join(extKeyUsages, ", "))
	}
	if certificate.BasicConstraintsValid {
		fmt.Printf("IsCA                  : %t\n", certificate.IsCA)
	}
	if len(certificate.DNSNames) > 0 {
		fmt.Printf("DNSNames              : %s\n", strings.Join(certificate.DNSNames, ", "))
	}
	if len(certificate.OCSPServer) > 0 {
		fmt.Printf("OCSPServer            : %s\n", strings.Join(certificate.OCSPServer, ", "))
	}
	if len(certificate.IssuingCertificateURL) > 0 {
		fmt.Printf("IssuingCertificateURL : %s\n", strings.Join(certificate.IssuingCertificateURL, ", "))
	}
	if len(certificate.CRLDistributionPoints) > 0 {
		fmt.Printf("CRLDistributionPoints : %s\n", strings.Join(certificate.CRLDistributionPoints, ", "))
	}
	if len(certificate.PolicyIdentifiers) > 0 {
		var policyIdentifiers []string
		for _, policyIdentifier := range certificate.PolicyIdentifiers {
			policyIdentifiers = append(policyIdentifiers, policyIdentifier.String())
		}
		fmt.Printf("PolicyIdentifiers     : %s\n", strings.Join(policyIdentifiers, ", "))
	}
	if len(certificate.SubjectKeyId) > 0 {
		fmt.Printf("SubjectKeyId          : %s\n", hex.EncodeToString(certificate.SubjectKeyId))
	}
	if len(certificate.AuthorityKeyId) > 0 {
		fmt.Printf("AuthorityKeyId        : %s\n", hex.EncodeToString(certificate.AuthorityKeyId))
	}

	if *verbose {
		sha1Fingerprint := sha1.Sum(certificate.Raw)
		fmt.Printf("SHA1Fingerprint       : %s\n", hex.EncodeToString(sha1Fingerprint[:]))
		sha256Fingerprint := sha256.Sum256(certificate.Raw)
		fmt.Printf("SHA256Fingerprint     : %s\n", hex.EncodeToString(sha256Fingerprint[:]))
		md5Fingerprint := md5.Sum(certificate.Raw)
		fmt.Printf("MD5Fingerprint        : %s\n", hex.EncodeToString(md5Fingerprint[:]))
		printCertificatePEM(certificate.Raw)
	}
}

/*
printOCSPDetails prints important OCSP response details / information
*/
func printOCSPDetails(rawOCSPResponse []byte, issuer *x509.Certificate) {

	response, err := ocsp.ParseResponse(rawOCSPResponse, issuer)
	if err != nil {
		fmt.Printf("error: parsing raw OSCP response failed\n")
		return
	}

	if *debug {
		printDump("OCSP response", response)
	}

	statusText := "error: unrecognised OCSP status"
	switch response.Status {
	case ocsp.Good:
		statusText = "Good"
	case ocsp.Revoked:
		statusText = "Revoked"
	case ocsp.Unknown:
		statusText = "Unknown"
	case ocsp.ServerFailed:
		statusText = "ServerFailed"
	}

	revocationReasonText := "error: unrecognised revocation reason"
	switch response.RevocationReason {
	case ocsp.Unspecified:
		revocationReasonText = "Unspecified"
	case ocsp.KeyCompromise:
		revocationReasonText = "KeyCompromise"
	case ocsp.CACompromise:
		revocationReasonText = "CACompromise"
	case ocsp.AffiliationChanged:
		revocationReasonText = "AffiliationChanged"
	case ocsp.Superseded:
		revocationReasonText = "Superseded"
	case ocsp.CessationOfOperation:
		revocationReasonText = "CessationOfOperation"
	case ocsp.CertificateHold:
		revocationReasonText = "CertificateHold"
	case ocsp.RemoveFromCRL:
		revocationReasonText = "RemoveFromCRL"
	case ocsp.PrivilegeWithdrawn:
		revocationReasonText = "PrivilegeWithdrawn"
	case ocsp.AACompromise:
		revocationReasonText = "AACompromise"
	}

	fmt.Printf("Status           : %v (%s)\n", response.Status, statusText)
	fmt.Printf("SerialNumber     : %v\n", response.SerialNumber)
	fmt.Printf("ProducedAt       : %v\n", response.ProducedAt)
	diff := start.Sub(response.ThisUpdate)
	fmt.Printf("ThisUpdate       : %v (was provided %d hours ago)\n", response.ThisUpdate, diff/(time.Hour))
	diff = response.NextUpdate.Sub(start)
	fmt.Printf("NextUpdate       : %v (will be provided in %d hours)\n", response.NextUpdate, diff/(time.Hour))
	fmt.Printf("RevokedAt        : %v\n", response.RevokedAt)
	fmt.Printf("RevocationReason : %v (%s)\n", response.RevocationReason, revocationReasonText)

	if *verbose {
		printOCSPResonsePEM(rawOCSPResponse)
	}
}

/*
fetchOCSPResponseFromService fetches certificate state from corresponding OCSP service
*/
func fetchOCSPResponseFromService(clientCert, issuerCert *x509.Certificate, ocspServer string) ([]byte, error) {

	opts := &ocsp.RequestOptions{Hash: crypto.SHA1}

	buffer, err := ocsp.CreateRequest(clientCert, issuerCert, opts)
	if err != nil {
		message := fmt.Sprintf("error: error <%v> at ocsp.CreateRequest()", err)
		return nil, errors.New(message)
	}

	httpRequest, err := http.NewRequest(http.MethodPost, ocspServer, bytes.NewBuffer(buffer))
	if err != nil {
		message := fmt.Sprintf("error: error <%v> at http.NewRequest()", err)
		return nil, errors.New(message)
	}

	ocspURL, err := url.Parse(ocspServer)
	if err != nil {
		message := fmt.Sprintf("error: error <%v> at url.Parse()", err)
		return nil, errors.New(message)
	}

	httpRequest.Header.Add("Content-Type", "application/ocsp-request")
	httpRequest.Header.Add("Accept", "application/ocsp-response")
	httpRequest.Header.Add("host", ocspURL.Host)

	httpClient := &http.Client{
		Timeout: time.Duration(*timeout) * time.Second,
	}

	httpResponse, err := httpClient.Do(httpRequest)
	if err != nil {
		message := fmt.Sprintf("error: error <%v> at httpClient.Do()", err)
		return nil, errors.New(message)
	}
	defer httpResponse.Body.Close()

	output, err := ioutil.ReadAll(httpResponse.Body)
	if err != nil {
		message := fmt.Sprintf("error: error <%v> at ioutil.ReadAll()", err)
		return nil, errors.New(message)
	}

	return output, nil
}

/*
buildKeyUsages builds an ordered slice with all key usages
*/
func buildKeyUsages(keyUsage x509.KeyUsage) []string {

	var keyUsageList []string

	if keyUsage >= (1 << 9) {
		keyUsageList = append(keyUsageList, "Unknown")
	}
	if Has(keyUsage, x509.KeyUsageDecipherOnly) {
		keyUsageList = append(keyUsageList, "DecipherOnly")
	}
	if Has(keyUsage, x509.KeyUsageEncipherOnly) {
		keyUsageList = append(keyUsageList, "EncipherOnly")
	}
	if Has(keyUsage, x509.KeyUsageCRLSign) {
		keyUsageList = append(keyUsageList, "CRLSign")
	}
	if Has(keyUsage, x509.KeyUsageCertSign) {
		keyUsageList = append(keyUsageList, "CertSign")
	}
	if Has(keyUsage, x509.KeyUsageKeyAgreement) {
		keyUsageList = append(keyUsageList, "KeyAgreement")
	}
	if Has(keyUsage, x509.KeyUsageDataEncipherment) {
		keyUsageList = append(keyUsageList, "DataEncipherment")
	}
	if Has(keyUsage, x509.KeyUsageKeyEncipherment) {
		keyUsageList = append(keyUsageList, "KeyEncipherment")
	}
	if Has(keyUsage, x509.KeyUsageContentCommitment) {
		keyUsageList = append(keyUsageList, "ContentCommitment")
	}
	if Has(keyUsage, x509.KeyUsageDigitalSignature) {
		keyUsageList = append(keyUsageList, "DigitalSignature")
	}

	return keyUsageList
}

// Has tests a bit
func Has(b, flag x509.KeyUsage) bool {

	return b&flag != 0
}

/*
buildExtKeyUsages builds an ordered slice with all extended key usages
*/
func buildExtKeyUsages(extKeyUsage []x509.ExtKeyUsage) []string {

	var extKeyUsageList []string

	for _, usage := range extKeyUsage {
		switch usage {
		case x509.ExtKeyUsageAny:
			extKeyUsageList = append(extKeyUsageList, "UsageAny")
		case x509.ExtKeyUsageServerAuth:
			extKeyUsageList = append(extKeyUsageList, "ServerAuth")
		case x509.ExtKeyUsageClientAuth:
			extKeyUsageList = append(extKeyUsageList, "ClientAuth")
		case x509.ExtKeyUsageCodeSigning:
			extKeyUsageList = append(extKeyUsageList, "CodeSigning")
		case x509.ExtKeyUsageEmailProtection:
			extKeyUsageList = append(extKeyUsageList, "EmailProtection")
		case x509.ExtKeyUsageIPSECEndSystem:
			extKeyUsageList = append(extKeyUsageList, "IPSECEndSystem")
		case x509.ExtKeyUsageIPSECTunnel:
			extKeyUsageList = append(extKeyUsageList, "IPSECTunnel")
		case x509.ExtKeyUsageIPSECUser:
			extKeyUsageList = append(extKeyUsageList, "IPSECUser")
		case x509.ExtKeyUsageTimeStamping:
			extKeyUsageList = append(extKeyUsageList, "TimeStamping")
		case x509.ExtKeyUsageOCSPSigning:
			extKeyUsageList = append(extKeyUsageList, "OCSPSigning")
		case x509.ExtKeyUsageMicrosoftServerGatedCrypto:
			extKeyUsageList = append(extKeyUsageList, "MicrosoftServerGatedCrypto")
		case x509.ExtKeyUsageNetscapeServerGatedCrypto:
			extKeyUsageList = append(extKeyUsageList, "NetscapeServerGatedCrypto")
		case x509.ExtKeyUsageMicrosoftCommercialCodeSigning:
			extKeyUsageList = append(extKeyUsageList, "MicrosoftCommercialCodeSigning")
		case x509.ExtKeyUsageMicrosoftKernelCodeSigning:
			extKeyUsageList = append(extKeyUsageList, "MicrosoftKernelCodeSigning")
		default:
			extKeyUsageList = append(extKeyUsageList, "Unknown")
		}
	}

	return extKeyUsageList
}

/*
printCertificatePEM prints the certificate in PEM format
*/
func printCertificatePEM(rawCertificate []byte) {

	var pemBuffer bytes.Buffer
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: rawCertificate,
	}

	if err := pem.Encode(&pemBuffer, block); err != nil {
		fmt.Printf("Error: unable to encode raw certificate, error = %v\n", err)
		return
	}

	fmt.Printf("\n%s", pemBuffer.String())
}

/*
printOCSPResonsePEM prints the OCSP response in PEM format
*/
func printOCSPResonsePEM(rawOCSPResponse []byte) {

	var pemBuffer bytes.Buffer
	block := &pem.Block{
		Type:  "OCSP RESPONSE",
		Bytes: rawOCSPResponse,
	}

	if err := pem.Encode(&pemBuffer, block); err != nil {
		fmt.Printf("Error: unable to encode raw OCSP response, error = %v\n", err)
		return
	}

	fmt.Printf("\n%s", pemBuffer.String())
}

/*
printDump prints (dumps) an arbitrary data object
*/
func printDump(objectname string, object interface{}) {

	fmt.Printf("\n-----BEGIN DUMP %s-----\n", objectname)
	fmt.Printf("%s", spew.Sdump(object))
	fmt.Printf("-----END DUMP %s-----\n\n", objectname)
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
	default:
		return "UNKNOWN"
	}
}

/*
getCipherSuite gets the Cipher Suite literal
*/
func getCipherSuite(cipherSuite uint16) string {

	switch cipherSuite {
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
	case tls.TLS_FALLBACK_SCSV:
		return "TLS_FALLBACK_SCSV"
	default:
		return "UNKNOWN"
	}
}

// reference output (for 'example.com:443')
var referenceOutput = `
  GENERAL INFORMATION ...
  Service : example.com:443
  Timeout : 19
  Verbose : false
  Debug   : false
  Time    : 2018-09-27 12:09:22 +0200 CEST
  
  TLS CONNECTION DETAILS ...
  Version           : 771 (0x0303, VersionTLS12)
  HandshakeComplete : true
  CipherSuite       : 49199 (0xc02f, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
  
  NETWORK ADDRESS DETAILS ...
  LocalAddr  : 192.168.178.55:56054
  RemoteAddr : 93.184.216.34:443
  
  CERTIFICATE DETAILS ...
  SignatureAlgorithm    : SHA256-RSA
  PublicKeyAlgorithm    : RSA
  Version               : 3
  SerialNumber          : 19132437207909210467858529073412672688
  Subject               : CN=www.example.org,OU=Technology,O=Internet Corporation for Assigned Names and Numbers,L=Los Angeles,ST=California,C=US
  Issuer                : CN=DigiCert SHA2 High Assurance Server CA,OU=www.digicert.com,O=DigiCert Inc,C=US
  NotBefore             : 2015-11-03 00:00:00 +0000 UTC (valid for 1121 days)
  NotAfter              : 2018-11-28 12:00:00 +0000 UTC (expires in 62 days)
  KeyUsage              : 5 (101, KeyEncipherment, DigitalSignature)
  ExtKeyUsage           : ServerAuth, ClientAuth
  IsCA                  : false
  DNSNames              : www.example.org, example.com, example.edu, example.net, example.org, www.example.com, www.example.edu, www.example.net
  OCSPServer            : http://ocsp.digicert.com
  IssuingCertificateURL : http://cacerts.digicert.com/DigiCertSHA2HighAssuranceServerCA.crt
  CRLDistributionPoints : http://crl3.digicert.com/sha2-ha-server-g4.crl, http://crl4.digicert.com/sha2-ha-server-g4.crl
  PolicyIdentifiers     : 2.16.840.1.114412.1.1, 2.23.140.1.2.2
  SubjectKeyId          : a64f601e1f2dd1e7f123a02a9516e4e89aea6e48
  AuthorityKeyId        : 5168ff90af0207753cccd9656462a212b859723b
  
  CERTIFICATE DETAILS ...
  SignatureAlgorithm    : SHA256-RSA
  PublicKeyAlgorithm    : RSA
  Version               : 3
  SerialNumber          : 6489877074546166222510380951761917343
  Subject               : CN=DigiCert SHA2 High Assurance Server CA,OU=www.digicert.com,O=DigiCert Inc,C=US
  Issuer                : CN=DigiCert High Assurance EV Root CA,OU=www.digicert.com,O=DigiCert Inc,C=US
  NotBefore             : 2013-10-22 12:00:00 +0000 UTC (valid for 5479 days)
  NotAfter              : 2028-10-22 12:00:00 +0000 UTC (expires in 3678 days)
  KeyUsage              : 97 (1100001, CRLSign, CertSign, DigitalSignature)
  ExtKeyUsage           : ServerAuth, ClientAuth
  IsCA                  : true
  OCSPServer            : http://ocsp.digicert.com
  CRLDistributionPoints : http://crl4.digicert.com/DigiCertHighAssuranceEVRootCA.crl
  PolicyIdentifiers     : 2.5.29.32.0
  SubjectKeyId          : 5168ff90af0207753cccd9656462a212b859723b
  AuthorityKeyId        : b13ec36903f8bf4701d498261a0802ef63642bc3
  
  OCSP DETAILS - STAPLED INFORMATION ...
  Status           : 0 (Good)
  SerialNumber     : 19132437207909210467858529073412672688
  ProducedAt       : 2018-09-26 21:40:02 +0000 UTC
  ThisUpdate       : 2018-09-26 21:40:02 +0000 UTC (was provided 12 hours ago)
  NextUpdate       : 2018-10-03 20:55:02 +0000 UTC (will be provided in 154 hours)
  RevokedAt        : 0001-01-01 00:00:00 +0000 UTC
  RevocationReason : 0 (Unspecified)
  
  OCSP DETAILS - SERVICE RESPONSE ...
  Status           : 0 (Good)
  SerialNumber     : 19132437207909210467858529073412672688
  ProducedAt       : 2018-09-27 03:39:56 +0000 UTC
  ThisUpdate       : 2018-09-27 03:39:56 +0000 UTC (was provided 6 hours ago)
  NextUpdate       : 2018-10-04 02:54:56 +0000 UTC (will be provided in 160 hours)
  RevokedAt        : 0001-01-01 00:00:00 +0000 UTC
  RevocationReason : 0 (Unspecified)
`
