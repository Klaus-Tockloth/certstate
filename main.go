/*
Purpose:
- monitor public key certificate

Description:
- Prints public key certificate details offered by tls service.

Releases:
- 0.1.0 - 2018/09/23 : initial release

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
- Useful commands:
  openssl s_client -showcerts -connect example.com:443

Links:
- https://www.feistyduck.com/library/openssl-cookbook/online/ch-testing-with-openssl.html
- https://godoc.org/golang.org/x/crypto/ocsp
- https://github.com/xenolf/lego/blob/master/acme/crypto.go
*/

package main

import (
	"bytes"
	"crypto"
	"crypto/tls"
	"crypto/x509"
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

	"golang.org/x/crypto/ocsp"
)

// general program info
var (
	progName    = os.Args[0]
	progVersion = "0.1.0"
	progDate    = "2018/09/23"
	progPurpose = "monitor public key certificate"
	progInfo    = "Prints public key certificate details offered by tls service."
)

// global settings
var timeout *int

/*
main starts this program
*/
func main() {

	timeout = flag.Int("timeout", 19, "communication timeout in seconds")

	flag.Usage = printUsage
	flag.Parse()

	// at least one argument required
	if len(flag.Args()) == 0 {
		fmt.Printf("\nError:\n  address:port argument (tls service) required.\n")
		printUsage()
	}

	// check timeout setting
	if *timeout < 1 {
		fmt.Printf("\nError:\n  Invalid setting <%v> for -timeout option.\n", *timeout)
		printUsage()
	}

	service := flag.Args()[0]

	config := &tls.Config{
		InsecureSkipVerify: true,
	}

	// connect to service with timeout
	dialer := &net.Dialer{
		Timeout: time.Duration(*timeout) * time.Second,
	}
	// fmt.Printf("\nConnecting to %q ...\n\n", service)
	conn, err := tls.DialWithDialer(dialer, "tcp", service, config)
	if err != nil {
		fmt.Printf("Error: unable to connect to service, error = %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("TLSService            : %s\n", service)
	fmt.Printf("Timeout               : %d\n", *timeout)
	fmt.Printf("Timestamp             : %s\n\n", time.Now().Format("2006-01-02 15:04:05 -0700 MST"))

	// log connection details
	logConnectionState(conn)

	// shut down the connection
	err = conn.Close()
	if err != nil {
		fmt.Printf("Error: unable to close connection, error = %v\n", err)
		os.Exit(1)
	}

	os.Exit(0)
}

/*
logConnectionState logs some data from the connection state
*/
func logConnectionState(conn *tls.Conn) {

	state := conn.ConnectionState()
	// fmt.Printf("Connection State ...\n%v\n", spew.Sdump(state))

	var issuerCertificate *x509.Certificate
	var issuerCommonName string

	// print some public key certificate data
	for index, certificate := range state.PeerCertificates {
		// fmt.Printf("certificate ...\n%s\n", spew.Sdump(certificate))
		if index == 0 {
			issuerCommonName = certificate.Issuer.CommonName
		}
		if index > 0 {
			if issuerCommonName == certificate.Subject.CommonName {
				issuerCertificate = certificate
			}
		}
		fmt.Printf("SignatureAlgorithm    : %s\n", certificate.SignatureAlgorithm)
		fmt.Printf("PublicKeyAlgorithm    : %s\n", certificate.PublicKeyAlgorithm)
		fmt.Printf("Version               : %v\n", certificate.Version)
		fmt.Printf("SerialNumber          : %s\n", certificate.SerialNumber)
		fmt.Printf("Subject               : %s\n", certificate.Subject)
		fmt.Printf("Issuer                : %s\n", certificate.Issuer)
		fmt.Printf("NotBefore             : %s\n", certificate.NotBefore)
		fmt.Printf("NotAfter              : %s\n", certificate.NotAfter)
		keyUsages := buildKeyUsages(certificate.KeyUsage)
		fmt.Printf("KeyUsage              : %v (%b, %s)\n", certificate.KeyUsage, certificate.KeyUsage, strings.Join(keyUsages, ", "))
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
		fmt.Printf("\n")
	}

	// stapled OCSP response from server (if any)
	if state.OCSPResponse != nil {
		if issuerCertificate != nil {
			ocspState := evaluateOCSPResponse(state.OCSPResponse, issuerCertificate)
			fmt.Printf("OCSPState (Stapled)   : %s\n", ocspState)
		}
	}

	// response from OCSP server (if defined)
	if len(state.PeerCertificates[0].OCSPServer) > 0 {
		if issuerCertificate != nil {
			leafCertificate := state.PeerCertificates[0]
			ocspServer := state.PeerCertificates[0].OCSPServer[0]
			ocspRawData, err := fetchOCSPResponseFromService(leafCertificate, issuerCertificate, ocspServer)
			if err != nil {
				fmt.Printf("Error: unable to fetch OCSP state from service, error = %v\n", err)
				os.Exit(1)
			}
			ocspState := evaluateOCSPResponse(ocspRawData, issuerCertificate)
			fmt.Printf("OCSPState (Service)   : %s\n", ocspState)
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
		"  - connects to a tls service and grabs the public key certificate\n" +
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
		"  - assess 'OCSPState (Stapled)' value\n" +
		"  - assess 'OCSPState (Service)' value\n" +
		"\n" +
		"Possible 'OCSPState' values:\n" +
		"  - Good\n" +
		"  - Revoked\n" +
		"  - Unknown\n" +
		"  - ServerFailed\n" +
		"  - error: unrecognised OCSP status\n" +
		"\n" +
		"Possible 'KeyUsage' values (binary):\n" +
		"  - 000000001 = DigitalSignature\n" +
		"  - 000000010 = ContentCommitment\n" +
		"  - 000000100 = KeyEncipherment\n" +
		"  - 000001000 = DataEncipherment\n" +
		"  - 000010000 = KeyAgreement\n" +
		"  - 000100000 = CertSign\n" +
		"  - 001000000 = CRLSign\n" +
		"  - 010000000 = EncipherOnly\n" +
		"  - 100000000 = DecipherOnly\n")

	fmt.Printf("\nUsage:\n")
	fmt.Printf("  %s [-timeout=sec] address:port\n", progName)

	fmt.Printf("\nExamples:\n")
	fmt.Printf("  %s example.com:443\n", progName)
	fmt.Printf("  %s -timeout=7 example.com:443\n", progName)

	fmt.Printf("\nOptions:\n")
	flag.PrintDefaults()

	fmt.Printf("\nArguments:\n")
	fmt.Printf("  address:port\n")
	fmt.Printf("        address (name/ip) and port of tls service\n")

	fmt.Printf("\nRemarks:\n" +
		"  - The timeout setting will be used:\n" +
		"    + as connection timeout when requesting the tls service\n" +
		"    + as overall timeout when requesting the OCSP service\n" +
		"  - empty or invalid values are not printed\n")

	fmt.Printf("\nReference output:\n%s\n", referenceOutput)

	os.Exit(1)
}

/*
evaluateOCSPResponse evaluates the OCSP response
*/
func evaluateOCSPResponse(bytes []byte, issuer *x509.Certificate) string {

	if issuer == nil {
		return "error: unsufficient arguments"
	}

	r, err := ocsp.ParseResponse(bytes, issuer)
	if err != nil {
		return "error: parsing OSCP response failed"
	}

	// fmt.Printf("OSCP response details ...\n")
	// fmt.Printf("Status           : %v\n", r.Status)
	// fmt.Printf("SerialNumber     : %v\n", r.SerialNumber)
	// fmt.Printf("ProducedAt       : %v\n", r.ProducedAt)
	// fmt.Printf("ThisUpdate       : %v\n", r.ThisUpdate)
	// fmt.Printf("NextUpdate       : %v\n", r.NextUpdate)
	// fmt.Printf("RevokedAt        : %v\n", r.RevokedAt)
	// fmt.Printf("RevocationReason : %v\n\n", r.RevocationReason)

	switch r.Status {
	case ocsp.Good:
		return "Good"
	case ocsp.Revoked:
		return "Revoked"
	case ocsp.Unknown:
		return "Unknown"
	case ocsp.ServerFailed:
		return "ServerFailed"
	default:
		return "error: unrecognised OCSP status"
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
		keyUsageList = append(keyUsageList, "UnknownUsage")
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

// reference output (for 'example.com:443')
var referenceOutput = `
  TLSService            : example.com:443
  Timeout               : 19
  Timestamp             : 2018-09-22 18:49:40 +0200 CEST
  
  SignatureAlgorithm    : SHA256-RSA
  PublicKeyAlgorithm    : RSA
  Version               : 3
  SerialNumber          : 19132437207909210467858529073412672688
  Subject               : CN=www.example.org,OU=Technology,O=Internet Corporation for Assigned Names and Numbers,L=Los Angeles,ST=California,C=US
  Issuer                : CN=DigiCert SHA2 High Assurance Server CA,OU=www.digicert.com,O=DigiCert Inc,C=US
  NotBefore             : 2015-11-03 00:00:00 +0000 UTC
  NotAfter              : 2018-11-28 12:00:00 +0000 UTC
  KeyUsage              : 5 (101, KeyEncipherment, DigitalSignature)
  IsCA                  : false
  DNSNames              : www.example.org, example.com, example.edu, example.net, example.org, www.example.com, www.example.edu, www.example.net
  OCSPServer            : http://ocsp.digicert.com
  IssuingCertificateURL : http://cacerts.digicert.com/DigiCertSHA2HighAssuranceServerCA.crt
  CRLDistributionPoints : http://crl3.digicert.com/sha2-ha-server-g4.crl, http://crl4.digicert.com/sha2-ha-server-g4.crl
  
  SignatureAlgorithm    : SHA256-RSA
  PublicKeyAlgorithm    : RSA
  Version               : 3
  SerialNumber          : 6489877074546166222510380951761917343
  Subject               : CN=DigiCert SHA2 High Assurance Server CA,OU=www.digicert.com,O=DigiCert Inc,C=US
  Issuer                : CN=DigiCert High Assurance EV Root CA,OU=www.digicert.com,O=DigiCert Inc,C=US
  NotBefore             : 2013-10-22 12:00:00 +0000 UTC
  NotAfter              : 2028-10-22 12:00:00 +0000 UTC
  KeyUsage              : 97 (1100001, CRLSign, CertSign, DigitalSignature)
  IsCA                  : true
  OCSPServer            : http://ocsp.digicert.com
  CRLDistributionPoints : http://crl4.digicert.com/DigiCertHighAssuranceEVRootCA.crl
  
  OCSPState (Stapled)   : Good
  OCSPState (Service)   : Good
`
