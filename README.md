# certstate

## Purpose

'certstate' is a simple helper tool to monitor the validity of public key certificates (digital certificate, SSL/TLS certificate, X.509 certificate). It grabs the certificate, checks the OCSP state (staple, service) and prints a subset of the collected data as plain text. It's up to you, to monitor the data and generate an alarm if the certificate has become invalid or threatens to become invalid.

## Usage

```txt
$ ./certstate

Error:
  address:port argument (TLS service) required.

Program:
  Name    : ./certstate
  Release : 0.6.0 - 2019/02/26
  Purpose : monitor public key certificate
  Info    : Prints public key certificate details offered by TLS service.

What does this tool do?
  - connects to a TLS service and grabs the public key certificate
  - if certificate contains OCSP stapling data: parses the data
  - if certificate contains link to OCSP service: requests the status
  - prints out a subset (the important part) of the collected data

Possible return values:
  - 0 = OK
  - >0 = NOK

How to check the validity of a public key certificate?
  - assess 'NotBefore' value of leaf certificate
  - assess 'NotAfter' value of leaf certificate
  - assess 'Status' value(s) of OCSP response(s)

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

Possible OCSP 'Status' values:
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

Usage:
  ./certstate [-timeout=sec] [-verbose] address:port

Examples:
  ./certstate example.com:443
  ./certstate -timeout=7 example.com:443
  ./certstate -verbose example.com:443

Options:
  -debug
    	prints internal representation of connection, certificate, OCSP response
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
  - empty or invalid values are not printed

Reference output (nonverbose):

  GENERAL INFORMATION ...
  Service : example.com:443
  Timeout : 19
  Verbose : false
  Debug   : false
  Time    : 2019-02-26 11:00:45 +0100 CET

  TLS CONNECTION DETAILS ...
  Version           : 772 (0x0304, VersionTLS13)
  HandshakeComplete : true
  CipherSuite       : 4866 (0x1302, TLS_AES_256_GCM_SHA384)

  NETWORK ADDRESS DETAILS ...
  LocalAddr  : 192.168.178.55:54968
  RemoteAddr : 93.184.216.34:443

  CERTIFICATE DETAILS ...
  SignatureAlgorithm    : SHA256-RSA
  PublicKeyAlgorithm    : RSA
  Version               : 3
  SerialNumber          : 21020869104500376438182461249190639870
  Subject               : CN=www.example.org,OU=Technology,O=Internet Corporation for Assigned Names and Numbers,L=Los Angeles,ST=California,C=US
  Issuer                : CN=DigiCert SHA2 Secure Server CA,O=DigiCert Inc,C=US
  NotBefore             : 2018-11-28 00:00:00 +0000 UTC (valid for 735 days)
  NotAfter              : 2020-12-02 12:00:00 +0000 UTC (expires in 645 days)
  KeyUsage              : 5 (101, KeyEncipherment, DigitalSignature)
  ExtKeyUsage           : ServerAuth, ClientAuth
  IsCA                  : false
  DNSNames              : www.example.org, example.com, example.edu, example.net, example.org, www.example.com, www.example.edu, www.example.net
  OCSPServer            : http://ocsp.digicert.com
  IssuingCertificateURL : http://cacerts.digicert.com/DigiCertSHA2SecureServerCA.crt
  CRLDistributionPoints : http://crl3.digicert.com/ssca-sha2-g6.crl, http://crl4.digicert.com/ssca-sha2-g6.crl
  PolicyIdentifiers     : 2.16.840.1.114412.1.1, 2.23.140.1.2.2
  SubjectKeyId          : 66986202e00991a7d9e336fb76c6b0bfa16da7be
  AuthorityKeyId        : 0f80611c823161d52f28e78d4638b42ce1c6d9e2

  CERTIFICATE DETAILS ...
  SignatureAlgorithm    : SHA256-RSA
  PublicKeyAlgorithm    : RSA
  Version               : 3
  SerialNumber          : 2646203786665923649276728595390119057
  Subject               : CN=DigiCert SHA2 Secure Server CA,O=DigiCert Inc,C=US
  Issuer                : CN=DigiCert Global Root CA,OU=www.digicert.com,O=DigiCert Inc,C=US
  NotBefore             : 2013-03-08 12:00:00 +0000 UTC (valid for 3652 days)
  NotAfter              : 2023-03-08 12:00:00 +0000 UTC (expires in 1471 days)
  KeyUsage              : 97 (1100001, CRLSign, CertSign, DigitalSignature)
  IsCA                  : true
  OCSPServer            : http://ocsp.digicert.com
  CRLDistributionPoints : http://crl3.digicert.com/DigiCertGlobalRootCA.crl, http://crl4.digicert.com/DigiCertGlobalRootCA.crl
  PolicyIdentifiers     : 2.5.29.32.0
  SubjectKeyId          : 0f80611c823161d52f28e78d4638b42ce1c6d9e2
  AuthorityKeyId        : 03de503556d14cbb66f0a3e21b1bc397b23dd155

  CERTIFICATE DETAILS ...
  SignatureAlgorithm    : SHA1-RSA
  PublicKeyAlgorithm    : RSA
  Version               : 3
  SerialNumber          : 10944719598952040374951832963794454346
  Subject               : CN=DigiCert Global Root CA,OU=www.digicert.com,O=DigiCert Inc,C=US
  Issuer                : CN=DigiCert Global Root CA,OU=www.digicert.com,O=DigiCert Inc,C=US
  NotBefore             : 2006-11-10 00:00:00 +0000 UTC (valid for 9131 days)
  NotAfter              : 2031-11-10 00:00:00 +0000 UTC (expires in 4639 days)
  KeyUsage              : 97 (1100001, CRLSign, CertSign, DigitalSignature)
  IsCA                  : true
  SubjectKeyId          : 03de503556d14cbb66f0a3e21b1bc397b23dd155
  AuthorityKeyId        : 03de503556d14cbb66f0a3e21b1bc397b23dd155

  OCSP DETAILS - STAPLED INFORMATION ...
  Status           : 0 (Good)
  SerialNumber     : 21020869104500376438182461249190639870
  ProducedAt       : 2019-02-25 06:26:59 +0000 UTC
  ThisUpdate       : 2019-02-25 06:26:59 +0000 UTC (was provided 27 hours ago)
  NextUpdate       : 2019-03-04 05:41:59 +0000 UTC (will be provided in 139 hours)
  RevokedAt        : 0001-01-01 00:00:00 +0000 UTC
  RevocationReason : 0 (Unspecified)

  OCSP DETAILS - SERVICE RESPONSE ...
  Status           : 0 (Good)
  SerialNumber     : 21020869104500376438182461249190639870
  ProducedAt       : 2019-02-26 06:26:58 +0000 UTC
  ThisUpdate       : 2019-02-26 06:26:58 +0000 UTC (was provided 3 hours ago)
  NextUpdate       : 2019-03-05 05:41:58 +0000 UTC (will be provided in 163 hours)
  RevokedAt        : 0001-01-01 00:00:00 +0000 UTC
  RevocationReason : 0 (Unspecified)
```

## Remarks

The master branch is used for program development and may be unstable.

## Releases

### 0.1.0, 2018/09/23

- initial release

### 0.2.0, 2018/09/24

- output format modified, verbose mode implemented

### 0.3.0, 2018/09/25

- added: time calculations, ExtKeyUsage, fingerprints

### 0.4.0, 2018/09/26

- added: SubjectKeyId, AuthorityKeyId, debug option, connection details, network details

### 0.5.0, 2018/09/27

- added: PolicyIdentifiers

### 0.6.0, 2019/02/26

- added: TLS 1.3 support
