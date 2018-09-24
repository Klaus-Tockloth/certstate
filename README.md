# certstate

## Purpose

'certstate' is a simple helper tool to monitor the validity of public key certificates (digital certificate, SSL/TLS certificate, X.509 certificate). It grabs the certificate, checks the OCSP state (staple, service) and prints a subset of the collected data as plain text. It's up to you, to monitor the data and generate an alarm if the certificate has become invalid or threatens to become invalid.

## Usage

```txt
$ ./certstate -help

Program:
  Name    : ./certstate
  Release : 0.2.0 - 2018/09/24
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
  -timeout int
      communication timeout in seconds (default 19)
  -verbose
      prints additional PEM formatted data (certificate, OCSP response)

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
  Service   : example.com:443
  Timeout   : 19
  Verbose   : false
  Timestamp : 2018-09-24 13:17:32 +0200 CEST
  
  CERTIFICATE DETAILS ...
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
  
  CERTIFICATE DETAILS ...
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
  
  OCSP DETAILS - STAPLED INFORMATION ...
  Status           : 0 (Good)
  SerialNumber     : 19132437207909210467858529073412672688
  ProducedAt       : 2018-09-24 03:39:53 +0000 UTC
  ThisUpdate       : 2018-09-24 03:39:53 +0000 UTC
  NextUpdate       : 2018-10-01 02:54:53 +0000 UTC
  RevokedAt        : 0001-01-01 00:00:00 +0000 UTC
  RevocationReason : 0 (Unspecified)
  
  OCSP DETAILS - SERVICE RESPONSE ...
  Status           : 0 (Good)
  SerialNumber     : 19132437207909210467858529073412672688
  ProducedAt       : 2018-09-24 09:39:54 +0000 UTC
  ThisUpdate       : 2018-09-24 09:39:54 +0000 UTC
  NextUpdate       : 2018-10-01 08:54:54 +0000 UTC
  RevokedAt        : 0001-01-01 00:00:00 +0000 UTC
  RevocationReason : 0 (Unspecified)
```

## Remarks

The master branch is used for program development and may be unstable.

## Releases

### 0.1.0, 2018/09/23

- initial release

### 0.2.0, 2018/09/24

- output format modified
- verbose mode implemented
