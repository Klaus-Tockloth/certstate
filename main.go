/*
Purpose:
- monitor public key certificate

Description:
- Prints public key certificate details offered by TLS service.

Releases:
- v0.1.0 - 2018/09/23 : initial release
- v0.2.0 - 2018/09/24 : output format modified, verbose mode implemented
- v0.3.0 - 2018/09/25 : added: time calculations, ExtKeyUsage, fingerprints
- v0.4.0 - 2018/09/26 : added: SubjectKeyId, AuthorityKeyId, debug option, connection details, network details
- v0.5.0 - 2018/09/27 : added: PolicyIdentifiers
- v0.5.1 - 2018/09/27 : small corrections
- v0.6.0 - 2019/02/26 : TLS 1.3 support (requires Go 1.12)
- v0.7.0 - 2019/11/02 : CRL support added, code restructed, options -ocsp and -crl added

Author:
- Klaus Tockloth

Copyright and license:
- Copyright (c) 2018, 2019 Klaus Tockloth
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
- Requires go 1.13 (or higher).

- OSCP server (multiple servers possible):
  No CA found, which provides more than one OCSP server.

- CRL Distribution Points (CDP, multiple CDPs often provided):
  This program downloads and checks every CRL (maybe overacted).
  CDPs provides by LDAP URLs are not supported.

  Links:
- https://godoc.org/golang.org/x/crypto/ocsp
*/

package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/davecgh/go-spew/spew"
)

// general program info
var (
	_, progName = filepath.Split(os.Args[0])
	progVersion = "v0.7.0"
	progDate    = "2019/11/02"
	progPurpose = "monitor public key certificate"
	progInfo    = "Prints public key certificate details offered by TLS service."
)

// global constants
const leftValue = "%-24s : "

// global objects / command line settings
var timeout *int
var verbose *bool
var debug *bool
var ocspValidation *bool
var crlValidation *bool
var start time.Time

/*
main starts this program
*/
func main() {

	timeout = flag.Int("timeout", 19, "communication timeout in seconds")
	verbose = flag.Bool("verbose", false, "adds fingerprints, PEM certificate, PEM OCSP response")
	debug = flag.Bool("debug", false, "prints internal representation of connection, certificate, OCSP response")
	ocspValidation = flag.Bool("ocsp", false, "validates leaf certificate against Online Certificate Status Protocol service (OCSP)")
	crlValidation = flag.Bool("crl", false, "validates leaf certificate against Certificate Revokation List(s) (CRL)")

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
	fmt.Printf(leftValue+"%s\n", "Command", strings.Join(os.Args, " "))
	fmt.Printf(leftValue+"%s\n", "Service", service)
	fmt.Printf(leftValue+"%d\n", "Timeout", *timeout)
	fmt.Printf(leftValue+"%t\n", "Verbose", *verbose)
	fmt.Printf(leftValue+"%t\n", "Debug", *debug)
	fmt.Printf(leftValue+"%t\n", "OCSP", *ocspValidation)
	fmt.Printf(leftValue+"%t\n", "CRL", *crlValidation)
	fmt.Printf(leftValue+"%s\n", "Time", start.Format("2006-01-02 15:04:05 -0700 MST"))

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
printConnectionState prints data from the connection state
*/
func printConnectionState(conn *tls.Conn) {

	state := conn.ConnectionState()

	// print connection details
	printConnectionDetails(conn)

	var leafCertificate *x509.Certificate
	var issuerCertificate *x509.Certificate
	var leafAuthorityKeyID string

	// print public key certificate details
	for index, certificate := range state.PeerCertificates {
		if index == 0 {
			leafCertificate = certificate
			leafAuthorityKeyID = string(certificate.AuthorityKeyId)
		}
		if index > 0 {
			if leafAuthorityKeyID == string(certificate.SubjectKeyId) {
				issuerCertificate = certificate
			}
		}
		fmt.Printf("\nCERTIFICATE DETAILS ...\n")
		printCertificateDetails(certificate)
	}

	// print stapled OCSP response from server (if any)
	if state.OCSPResponse != nil && issuerCertificate != nil {
		fmt.Printf("\nOCSP DETAILS - STAPLED INFORMATION ...\n")
		printOCSPDetails(state.OCSPResponse, issuerCertificate)
	}

	if *ocspValidation {
		// print response from OCSP server (if defined)
		if len(leafCertificate.OCSPServer) > 0 && issuerCertificate != nil {
			fmt.Printf("\nOCSP DETAILS - SERVICE RESPONSE ...\n")
			rawOCSPResponse, err := fetchOCSPResponseFromService(leafCertificate, issuerCertificate, leafCertificate.OCSPServer[0])
			if err != nil {
				fmt.Printf("Error: unable to fetch OCSP state from service, error = %v\n", err)
			}
			printOCSPDetails(rawOCSPResponse, issuerCertificate)
		}
	}

	if *crlValidation {
		// print revocation status from CRLs (if any)
		if len(leafCertificate.CRLDistributionPoints) > 0 && issuerCertificate != nil {
			for _, crlDistributionPoint := range leafCertificate.CRLDistributionPoints {
				printCRLDetails(crlDistributionPoint, leafCertificate.SerialNumber, issuerCertificate)
			}
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
		"  - if requested: validates leaf certificate against OCSP service\n" +
		"  - if requested: validates leaf certificate against CRL\n" +
		"  - prints out a subset (the important part) of the collected data\n" +
		"\n" +
		"Possible return values:\n" +
		"  - 0 = OK\n" +
		"  - >0 = NOK\n" +
		"\n" +
		"How to check the validity of a public key certificate?\n" +
		"  - assess 'NotBefore' value of leaf certificate\n" +
		"  - assess 'NotAfter' value of leaf certificate\n" +
		"  - assess 'CertificateStatus' value(s) of OCSP response(s)\n" +
		"  - assess 'CertificateStatus' value(s) of CRL validation(s)\n" +
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
		"Possible OCSP 'CertificateStatus' values:\n" +
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
		"  - 10 = AACompromise\n" +
		"\n" +
		"Possible CRL 'CertificateStatus' values:\n" +
		"  - Good\n" +
		"  - Revoked\n" +
		"\n" +
		"Possible CRL 'RevocationReason' values:\n" +
		"  - Id=ExtensionId, Value=ExtensionValue\n")

	fmt.Printf("\nUsage:\n")
	fmt.Printf("  %s [-timeout=sec] [-verbose] [-ocsp] [-crl] address:port\n", progName)

	fmt.Printf("\nExamples:\n")
	fmt.Printf("  %s -ocsp example.com:443\n", progName)
	fmt.Printf("  %s -timeout=7 example.com:443\n", progName)
	fmt.Printf("  %s -verbose example.com:443\n", progName)
	fmt.Printf("  %s -crl example.com:443\n", progName)

	fmt.Printf("\nOptions:\n")
	flag.PrintDefaults()

	fmt.Printf("\nArguments:\n")
	fmt.Printf("  address:port\n")
	fmt.Printf("        address (name/ip) and port of TLS service\n")

	fmt.Printf("\nRemarks:\n" +
		"  - The timeout setting will be used:\n" +
		"    + as connection timeout when requesting the TLS service\n" +
		"    + as overall timeout when requesting the OCSP service\n" +
		"    + as overall timeout when fetching a CRL\n" +
		"  - empty or invalid values are not printed\n")

	fmt.Printf("\nReference output:\n%s\n", referenceOutput)

	os.Exit(1)
}

/*
printDump prints (dumps) an arbitrary data object
*/
func printDump(objectname string, object interface{}) {

	fmt.Printf("\n-----BEGIN DUMP %s-----\n", objectname)
	fmt.Printf("%s", spew.Sdump(object))
	fmt.Printf("-----END DUMP %s-----\n\n", objectname)
}

// reference output
var referenceOutput = `
GENERAL INFORMATION ...
Command                  : ./certstate -ocsp -crl example.com:443
Service                  : example.com:443
Timeout                  : 19
Verbose                  : false
Debug                    : false
OCSP                     : true
CRL                      : true
Time                     : 2019-11-02 14:35:54 +0100 CET

TLS CONNECTION DETAILS ...
Version                  : 772 (0x0304, VersionTLS13)
HandshakeComplete        : true
CipherSuite              : 4866 (0x1302, TLS_AES_256_GCM_SHA384)

NETWORK ADDRESS DETAILS ...
LocalAddr                : 192.168.178.55:50398
LocalHost                : Klauss-MBP.fritz.box
RemoteAddr               : 93.184.216.34:443

CERTIFICATE DETAILS ...
SignatureAlgorithm       : SHA256-RSA
PublicKeyAlgorithm       : RSA
Version                  : 3
SerialNumber             : 21020869104500376438182461249190639870
Subject                  : CN=www.example.org,OU=Technology,O=Internet Corporation for Assigned Names and Numbers,L=Los Angeles,ST=California,C=US
Issuer                   : CN=DigiCert SHA2 Secure Server CA,O=DigiCert Inc,C=US
NotBefore                : 2018-11-28 00:00:00 +0000 UTC (valid for 735 days)
NotAfter                 : 2020-12-02 12:00:00 +0000 UTC (expires in 395 days)
KeyUsage                 : 5 (101, KeyEncipherment, DigitalSignature)
ExtKeyUsage              : ServerAuth, ClientAuth
IsCA                     : false
DNSNames                 : www.example.org, example.com, example.edu, example.net, example.org, www.example.com, www.example.edu, www.example.net
OCSPServer               : http://ocsp.digicert.com
IssuingCertificateURL    : http://cacerts.digicert.com/DigiCertSHA2SecureServerCA.crt
CRLDistributionPoints    : http://crl3.digicert.com/ssca-sha2-g6.crl, http://crl4.digicert.com/ssca-sha2-g6.crl
PolicyIdentifiers        : 2.16.840.1.114412.1.1, 2.23.140.1.2.2 (organization validation)
SubjectKeyId             : 66986202e00991a7d9e336fb76c6b0bfa16da7be
AuthorityKeyId           : 0f80611c823161d52f28e78d4638b42ce1c6d9e2

CERTIFICATE DETAILS ...
SignatureAlgorithm       : SHA256-RSA
PublicKeyAlgorithm       : RSA
Version                  : 3
SerialNumber             : 2646203786665923649276728595390119057
Subject                  : CN=DigiCert SHA2 Secure Server CA,O=DigiCert Inc,C=US
Issuer                   : CN=DigiCert Global Root CA,OU=www.digicert.com,O=DigiCert Inc,C=US
NotBefore                : 2013-03-08 12:00:00 +0000 UTC (valid for 3652 days)
NotAfter                 : 2023-03-08 12:00:00 +0000 UTC (expires in 1221 days)
KeyUsage                 : 97 (1100001, CRLSign, CertSign, DigitalSignature)
IsCA                     : true
OCSPServer               : http://ocsp.digicert.com
CRLDistributionPoints    : http://crl3.digicert.com/DigiCertGlobalRootCA.crl, http://crl4.digicert.com/DigiCertGlobalRootCA.crl
PolicyIdentifiers        : 2.5.29.32.0
SubjectKeyId             : 0f80611c823161d52f28e78d4638b42ce1c6d9e2
AuthorityKeyId           : 03de503556d14cbb66f0a3e21b1bc397b23dd155

CERTIFICATE DETAILS ...
SignatureAlgorithm       : SHA1-RSA
PublicKeyAlgorithm       : RSA
Version                  : 3
SerialNumber             : 10944719598952040374951832963794454346
Subject                  : CN=DigiCert Global Root CA,OU=www.digicert.com,O=DigiCert Inc,C=US
Issuer                   : CN=DigiCert Global Root CA,OU=www.digicert.com,O=DigiCert Inc,C=US
NotBefore                : 2006-11-10 00:00:00 +0000 UTC (valid for 9131 days)
NotAfter                 : 2031-11-10 00:00:00 +0000 UTC (expires in 4390 days)
KeyUsage                 : 97 (1100001, CRLSign, CertSign, DigitalSignature)
IsCA                     : true
SubjectKeyId             : 03de503556d14cbb66f0a3e21b1bc397b23dd155
AuthorityKeyId           : 03de503556d14cbb66f0a3e21b1bc397b23dd155

OCSP DETAILS - STAPLED INFORMATION ...
CertificateStatus        : Good
SerialNumber             : 21020869104500376438182461249190639870
ProducedAt               : 2019-11-01 05:27:38 +0000 UTC
ThisUpdate               : 2019-11-01 05:27:38 +0000 UTC (was provided 32 hours ago)
NextUpdate               : 2019-11-08 04:42:38 +0000 UTC (will be provided in 135 hours)

OCSP DETAILS - SERVICE RESPONSE ...
CertificateStatus        : Good
SerialNumber             : 21020869104500376438182461249190639870
ProducedAt               : 2019-11-02 05:27:43 +0000 UTC
ThisUpdate               : 2019-11-02 05:27:43 +0000 UTC (was provided 8 hours ago)
NextUpdate               : 2019-11-09 04:42:43 +0000 UTC (will be provided in 159 hours)

CRL DETAILS ...
DistributionPoint        : http://crl3.digicert.com/ssca-sha2-g6.crl
DownloadSupport          : Yes
ReadingStatus            : Ok
Signature                : Valid
Version                  : 1
Issuer                   : CN=DigiCert SHA2 Secure Server CA,O=DigiCert Inc,C=US
ThisUpdate               : 2019-11-01 22:48:32 +0000 UTC (was provided 14 hours ago)
NextUpdate               : 2019-11-11 22:48:32 +0000 UTC (will be provided in 225 hours)
Extension                : Id=2.5.29.35, Value=[48 22 128 20 15 128 97 28 130 49 97 213 47 40 231 141 70 56 180 44 225 198 217 226]
Extension                : Id=2.5.29.20, Value=[2 2 2 208]
Extension                : Id=2.5.29.28, Value=[48 47 160 45 160 43 134 41 104 116 116 112 58 47 47 99 114 108 51 46 100 105 103 105 99 101 114 116 46 99 111 109 47 115 115 99 97 45 115 104 97 50 45 103 54 46 99 114 108]
CertificateStatus        : Good
SerialNumber             : 21020869104500376438182461249190639870

CRL DETAILS ...
DistributionPoint        : http://crl4.digicert.com/ssca-sha2-g6.crl
DownloadSupport          : Yes
ReadingStatus            : Ok
Signature                : Valid
Version                  : 1
Issuer                   : CN=DigiCert SHA2 Secure Server CA,O=DigiCert Inc,C=US
ThisUpdate               : 2019-11-01 22:48:32 +0000 UTC (was provided 14 hours ago)
NextUpdate               : 2019-11-11 22:48:32 +0000 UTC (will be provided in 225 hours)
Extension                : Id=2.5.29.35, Value=[48 22 128 20 15 128 97 28 130 49 97 213 47 40 231 141 70 56 180 44 225 198 217 226]
Extension                : Id=2.5.29.20, Value=[2 2 2 208]
Extension                : Id=2.5.29.28, Value=[48 47 160 45 160 43 134 41 104 116 116 112 58 47 47 99 114 108 51 46 100 105 103 105 99 101 114 116 46 99 111 109 47 115 115 99 97 45 115 104 97 50 45 103 54 46 99 114 108]
CertificateStatus        : Good
SerialNumber             : 21020869104500376438182461249190639870
`
