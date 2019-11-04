package main

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/crypto/ocsp"
)

/*
printOCSPDetails prints important OCSP response details
*/
func printOCSPDetails(rawOCSPResponse []byte, issuer *x509.Certificate) {

	response, err := ocsp.ParseResponse(rawOCSPResponse, issuer)
	if err != nil {
		fmt.Printf("Error: unable to parse raw OCSP response, error = %v\n", err)
		return
	}

	if debug {
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

	fmt.Printf(leftValue+"%v\n", "CertificateStatus", statusText)
	fmt.Printf(leftValue+"%v\n", "SerialNumber", response.SerialNumber)
	fmt.Printf(leftValue+"%v\n", "ProducedAt", response.ProducedAt)
	diff := start.Sub(response.ThisUpdate)
	fmt.Printf(leftValue+"%v (was provided %d hours ago)\n", "ThisUpdate", response.ThisUpdate, diff/(time.Hour))
	diff = response.NextUpdate.Sub(start)
	fmt.Printf(leftValue+"%v (will be provided in %d hours)\n", "NextUpdate", response.NextUpdate, diff/(time.Hour))

	if response.Status == ocsp.Revoked {
		fmt.Printf(leftValue+"%v\n", "RevokedAt", response.RevokedAt)
		fmt.Printf(leftValue+"%v (%s)\n", "RevocationReason", response.RevocationReason, revocationReasonText)
	}

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
