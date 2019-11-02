# certstate

## Purpose

'certstate' is a simple helper tool to monitor the validity of public key certificates (digital certificate, SSL/TLS certificate, X.509 certificate). It grabs the certificate, checks the OCSP state (staple, service), checks the CRL state (all lists), and prints a subset of the collected data as plain text. It's up to you, to monitor the data and generate an alarm if the certificate has become invalid or threatens to become invalid.

## Usage

```txt
$ ./certstate

Error:
  address:port argument (TLS service) required.

Program:
  Name    : certstate
  Release : v0.7.0 - 2019/11/02
  Purpose : monitor public key certificate
  Info    : Prints public key certificate details offered by TLS service.

What does this tool do?
  - connects to a TLS service and grabs the public key certificate
  - if certificate contains OCSP stapling data: parses the data
  - if requested: validates leaf certificate against OCSP service
  - if requested: validates leaf certificate against CRL
  - prints out a subset (the important part) of the collected data

Possible return values:
  - 0 = OK
  - >0 = NOK

How to check the validity of a public key certificate?
  - assess 'NotBefore' value of leaf certificate
  - assess 'NotAfter' value of leaf certificate
  - assess 'CertificateStatus' value(s) of OCSP response(s)
  - assess 'CertificateStatus' value(s) of CRL validation(s)

Possible certificate 'KeyUsage' values (binary encoded):
  - 000000001 = DigitalSignature
  - 000000010 = ContentCommitment
  - 000000100 = KeyEncipherment
  - 000001000 = DataEncipherment
  - 000010000 = KeyAgreement
  - 000100000 = CertSign
  - 001000000 = CRLSign
  - 010000000 = EncipherOnly
  - 100000000 = DecipherOnly

Possible certificate 'ExtKeyUsage' values:
  - Any
  - ServerAuth
  - ClientAuth
  - CodeSigning
  - EmailProtection
  - IPSECEndSystem
  - IPSECTunnel
  - IPSECUser
  - TimeStamping
  - OCSPSigning
  - MicrosoftServerGatedCrypto
  - NetscapeServerGatedCrypto
  - MicrosoftCommercialCodeSigning
  - MicrosoftKernelCodeSigning

Possible OCSP 'CertificateStatus' values:
  - Good
  - Revoked
  - Unknown
  - ServerFailed

Possible OCSP 'RevocationReason' values:
  - 0 = Unspecified
  - 1 = KeyCompromise
  - 2 = CACompromise
  - 3 = AffiliationChanged
  - 4 = Superseded
  - 5 = CessationOfOperation
  - 6 = CertificateHold
  - 8 = RemoveFromCRL
  - 9 = PrivilegeWithdrawn
  - 10 = AACompromise

Possible CRL 'CertificateStatus' values:
  - Good
  - Revoked

Possible CRL 'RevocationReason' values:
  - Id=ExtensionId, Value=ExtensionValue

Usage:
  certstate [-timeout=sec] [-verbose] [-ocsp] [-crl] address:port

Examples:
  certstate -ocsp example.com:443
  certstate -timeout=7 example.com:443
  certstate -verbose example.com:443
  certstate -crl example.com:443

Options:
  -crl
    	validates leaf certificate against Certificate Revokation List(s) (CRL)
  -debug
    	prints internal representation of connection, certificate, OCSP response
  -ocsp
    	validates leaf certificate against Online Certificate Status Protocol service (OCSP)
  -timeout int
    	communication timeout in seconds (default 19)
  -verbose
    	adds fingerprints, PEM certificate, PEM OCSP response

Arguments:
  address:port
        address (name/ip) and port of TLS service

Remarks:
  - The timeout setting will be used:
    + as connection timeout when requesting the TLS service
    + as overall timeout when requesting the OCSP service
    + as overall timeout when fetching a CRL
  - empty or invalid values are not printed

Reference output:

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
```

## Remarks

The master branch is used for program development and may be unstable.

## Releases

### v0.1.0, 2018/09/23

- initial release

### v0.2.0, 2018/09/24

- output format modified, verbose mode implemented

### v0.3.0, 2018/09/25

- added: time calculations, ExtKeyUsage, fingerprints

### v0.4.0, 2018/09/26

- added: SubjectKeyId, AuthorityKeyId, debug option, connection details, network details

### v0.5.0, 2018/09/27

- added: PolicyIdentifiers

### v0.6.0, 2019/02/26

- added: TLS 1.3 support

### v0.7.0, 2019/11/02

- CRL support added, code restructed, options -ocsp and -crl implemented
