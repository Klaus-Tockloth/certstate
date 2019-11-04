package main

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"
	"time"
)

/*
printCertificateDetails prints important certificate details
*/
func printCertificateDetails(certificate *x509.Certificate) {

	if debug {
		printDump("certificate", certificate)
	}

	// basics
	fmt.Printf(leftValue+"%s\n", "SignatureAlgorithm", certificate.SignatureAlgorithm)
	fmt.Printf(leftValue+"%s\n", "PublicKeyAlgorithm", certificate.PublicKeyAlgorithm)
	fmt.Printf(leftValue+"%v\n", "Version", certificate.Version)
	fmt.Printf(leftValue+"%s\n", "SerialNumber", certificate.SerialNumber)
	fmt.Printf(leftValue+"%s\n", "Subject", certificate.Subject)
	fmt.Printf(leftValue+"%s\n", "Issuer", certificate.Issuer)
	diff := certificate.NotAfter.Sub(certificate.NotBefore)
	fmt.Printf(leftValue+"%s (valid for %d days)\n", "NotBefore", certificate.NotBefore, diff/(time.Hour*24))
	diff = certificate.NotAfter.Sub(start)
	fmt.Printf(leftValue+"%s (expires in %d days)\n", "NotAfter", certificate.NotAfter, diff/(time.Hour*24))

	// extensions (optional)
	if certificate.KeyUsage > 0 {
		keyUsages := buildKeyUsages(certificate.KeyUsage)
		fmt.Printf(leftValue+"%v (%b, %s)\n", "KeyUsage", certificate.KeyUsage, certificate.KeyUsage, strings.Join(keyUsages, ", "))
	}
	if len(certificate.ExtKeyUsage) > 0 {
		extKeyUsages := buildExtKeyUsages(certificate.ExtKeyUsage)
		fmt.Printf(leftValue+"%s\n", "ExtKeyUsage", strings.Join(extKeyUsages, ", "))
	}
	if certificate.BasicConstraintsValid {
		fmt.Printf(leftValue+"%t\n", "IsCA", certificate.IsCA)
	}
	if len(certificate.DNSNames) > 0 {
		fmt.Printf(leftValue+"%s\n", "DNSNames", strings.Join(certificate.DNSNames, ", "))
	}
	if len(certificate.OCSPServer) > 0 {
		fmt.Printf(leftValue+"%s\n", "OCSPServer", strings.Join(certificate.OCSPServer, ", "))
	}
	if len(certificate.IssuingCertificateURL) > 0 {
		fmt.Printf(leftValue+"%s\n", "IssuingCertificateURL", strings.Join(certificate.IssuingCertificateURL, ", "))
	}
	if len(certificate.CRLDistributionPoints) > 0 {
		fmt.Printf(leftValue+"%s\n", "CRLDistributionPoints", strings.Join(certificate.CRLDistributionPoints, ", "))
	}
	if len(certificate.PolicyIdentifiers) > 0 {
		var policyIdentifiers []string
		for _, policyIdentifier := range certificate.PolicyIdentifiers {
			pi := policyIdentifier.String()
			switch pi {
			case "2.23.140.1.2.1":
				pi += " (domain validation)"
			case "2.23.140.1.2.2":
				pi += " (organization validation)"
			case "2.23.140.1.2.3":
				pi += " (extended validation)"
			}
			policyIdentifiers = append(policyIdentifiers, pi)
		}
		fmt.Printf(leftValue+"%s\n", "PolicyIdentifiers", strings.Join(policyIdentifiers, ", "))
	}
	if len(certificate.SubjectKeyId) > 0 {
		fmt.Printf(leftValue+"%s\n", "SubjectKeyId", hex.EncodeToString(certificate.SubjectKeyId))
	}
	if len(certificate.AuthorityKeyId) > 0 {
		fmt.Printf(leftValue+"%s\n", "AuthorityKeyId", hex.EncodeToString(certificate.AuthorityKeyId))
	}

	if *verbose {
		sha1Fingerprint := sha1.Sum(certificate.Raw)
		fmt.Printf(leftValue+"%s\n", "SHA1Fingerprint", hex.EncodeToString(sha1Fingerprint[:]))
		sha256Fingerprint := sha256.Sum256(certificate.Raw)
		fmt.Printf(leftValue+"%s\n", "SHA256Fingerprint", hex.EncodeToString(sha256Fingerprint[:]))
		md5Fingerprint := md5.Sum(certificate.Raw)
		fmt.Printf(leftValue+"%s\n", "MD5Fingerprint", hex.EncodeToString(md5Fingerprint[:]))
		printCertificatePEM(certificate.Raw)
	}
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
