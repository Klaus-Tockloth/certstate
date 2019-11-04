package main

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"net/url"
	"time"
)

/*
printCRLDetails verifies serial number of leaf certificate against CRL and prints the results.
*/
func printCRLDetails(crlDistributionPoint string, serialNumber *big.Int, issuerCertificate *x509.Certificate) {

	fmt.Printf("\nCRL DETAILS ...\n")
	fmt.Printf(leftValue+"%v\n", "DistributionPoint", crlDistributionPoint)

	// parse CRLDistributionPoint to filter out unsupported URL schemes
	urlDetails, err := url.Parse(crlDistributionPoint)
	if err != nil {
		fmt.Printf(leftValue+"No (invalid URL, parsing error <%v>)\n", "DownloadSupport", err)
		return
	}

	if urlDetails.Scheme == "ldap" {
		fmt.Printf(leftValue+"No (ldap not supported)\n", "DownloadSupport")
		return
	}
	fmt.Printf(leftValue+"Yes\n", "DownloadSupport")

	rawCRL, err := fetchCRLfromCDP(crlDistributionPoint)
	if err != nil {
		fmt.Printf(leftValue+"Error (%v)\n", "ReadingStatus", err)
		return
	}

	crl, err := x509.ParseCRL(rawCRL)
	if err != nil {
		fmt.Printf(leftValue+"Error (%v)\n", "ReadingStatus", err)
		return
	}
	fmt.Printf(leftValue+"Ok\n", "ReadingStatus")

	// check CRL signature
	err = issuerCertificate.CheckCRLSignature(crl)
	if err != nil {
		fmt.Printf(leftValue+"Not Valid (%v)\n", "Signature", err)
		return
	}
	fmt.Printf(leftValue+"Valid\n", "Signature")

	// print CRL details
	fmt.Printf(leftValue+"%v\n", "Version", crl.TBSCertList.Version)
	fmt.Printf(leftValue+"%v\n", "Issuer", crl.TBSCertList.Issuer)
	diff := start.Sub(crl.TBSCertList.ThisUpdate)
	fmt.Printf(leftValue+"%v (was provided %d hours ago)\n", "ThisUpdate", crl.TBSCertList.ThisUpdate, diff/(time.Hour))
	diff = crl.TBSCertList.NextUpdate.Sub(start)
	fmt.Printf(leftValue+"%v (will be provided in %d hours)\n", "NextUpdate", crl.TBSCertList.NextUpdate, diff/(time.Hour))
	for _, extension := range crl.TBSCertList.Extensions {
		fmt.Printf(leftValue+"Id=%v, Value=%v\n", "Extension", extension.Id, extension.Value)
	}

	// check serial number of leaf certificate against CRL
	certificateStatus := "Good"

	// test with arbitrary serial number (e.g. revoked certificate)
	// serialNumber.SetString("0DBBB048C52F232547BEC91FCBE7598A", 16)

	var revokationEntry pkix.RevokedCertificate
	for _, revoked := range crl.TBSCertList.RevokedCertificates {
		if serialNumber.Cmp(revoked.SerialNumber) == 0 {
			// certificate revoked
			certificateStatus = "Revoked"
			revokationEntry = revoked
			break
		}
	}
	fmt.Printf(leftValue+"%v\n", "CertificateStatus", certificateStatus)
	fmt.Printf(leftValue+"%v\n", "SerialNumber", serialNumber)

	if certificateStatus == "Revoked" {
		fmt.Printf(leftValue+"%v\n", "RevokedAT", revokationEntry.RevocationTime)
		if len(revokationEntry.Extensions) > 0 {
			for _, extension := range revokationEntry.Extensions {
				fmt.Printf(leftValue+"Id=%v, Value=%v\n", "RevocationReason", extension.Id, extension.Value)
			}
		} else {
			fmt.Printf(leftValue+"Unspecified\n", "RevocationReason")
		}
	}

	if *verbose {
		printCRLPEM(rawCRL)
	}

}

/*
fetchCRLfromCDP fetches certificate revocation list (CRL) from CRL distribution point (CDP)
*/
func fetchCRLfromCDP(crlURL string) ([]byte, error) {

	httpClient := &http.Client{
		Timeout: time.Duration(*timeout) * time.Second,
	}

	httpResponse, err := httpClient.Get(crlURL)
	if err != nil {
		message := fmt.Sprintf("error: error <%v> at httpClient.Do()", err)
		return nil, errors.New(message)
	}
	defer httpResponse.Body.Close()

	if httpResponse.StatusCode >= 300 {
		message := fmt.Sprintf("error: unexpected http status code <%v> at httpClient.Get()", httpResponse.StatusCode)
		return nil, errors.New(message)
	}

	output, err := ioutil.ReadAll(httpResponse.Body)
	if err != nil {
		message := fmt.Sprintf("error: error <%v> at ioutil.ReadAll()", err)
		return nil, errors.New(message)
	}

	return output, nil
}

/*
printCRLPEM prints CRL in PEM format
*/
func printCRLPEM(rawCRL []byte) {

	pemCRLPrefix := []byte("-----BEGIN X509 CRL")

	if bytes.HasPrefix(rawCRL, pemCRLPrefix) {
		// CRL is already PEM-formatted
		fmt.Printf("\n%s", string(rawCRL))
		return
	}

	var pemBuffer bytes.Buffer
	block := &pem.Block{
		Type:  "X509 CRL",
		Bytes: rawCRL,
	}

	if err := pem.Encode(&pemBuffer, block); err != nil {
		fmt.Printf("Error: unable to encode CRL, error = %v\n", err)
		return
	}

	fmt.Printf("\n%s", pemBuffer.String())
}
