/*
Code for demonstrating hiding a file inside a CRL.
Written by: Jason Reaves
ver1 - 8Feb2018

MIT License

Copyright (c) 2018 Jason Reaves

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"io/ioutil"
	"math/big"
	"time"
)

var bsize = 64

func main() {
	//Generate a private key and a certificate to create the CRL
	priv, _ := rsa.GenerateKey(rand.Reader, 4096)
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1337),
		Subject: pkix.Name{
			Country:            []string{"Neuland"},
			Organization:       []string{"Example Org"},
			OrganizationalUnit: []string{"Auto"},
			CommonName:         "EICAR",
		},
		Issuer: pkix.Name{
			Country:            []string{"Neuland"},
			Organization:       []string{"Skynet"},
			OrganizationalUnit: []string{"Computer Emergency Response Team"},
			Locality:           []string{"Neuland"},
			Province:           []string{"Neuland"},
			StreetAddress:      []string{"Mainstreet 23"},
			PostalCode:         []string{"12345"},
			SerialNumber:       "23",
			CommonName:         "EICAR",
		},
		SignatureAlgorithm:    x509.SHA512WithRSA,
		PublicKeyAlgorithm:    x509.ECDSA,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, 10),
		BasicConstraintsValid: true,
		IsCA:        true,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}
	//Assuming the file to be encoded into a CRL is named test
	fdata, _ := ioutil.ReadFile("test")
	sz := len(fdata)

	//We can store the files hash in the last revoked cert in the list as an extension
	h := sha256.New()
	h.Write(fdata)
	extSubKeyId := pkix.Extension{}
	extSubKeyId.Id = asn1.ObjectIdentifier{2, 5, 29, 14}
	extSubKeyId.Critical = true
	extSubKeyId.Value = h.Sum(nil)

	//Generic time values needed
	now := time.Unix(1000, 0)
	expiry := time.Unix(10000, 0)

	//Force the int and byte conversion to not strip nulls
	temp := []byte("\x01")
	iterations := sz / bsize
	//CRLs can hold sequences of ASN.1 encoded revoked certificates
	revokedCerts := []pkix.RevokedCertificate{}
	for i := 0; i < iterations; i++ {
		n := big.NewInt(0)
		n.SetBytes(append(temp, fdata[i*bsize:(i+1)*bsize]...))
		revokedCerts = append(revokedCerts, pkix.RevokedCertificate{SerialNumber: n, RevocationTime: now})
	}
	//The last blob of data might be less than bsize use this to store our hash
	//Edge case would be a file length exactly divisible by bsize
	//In this event we end up with an extra record with a serial number of 01 and recovery slices still work fine appending an empty byte array
	n := big.NewInt(0)
	n.SetBytes(append(temp, fdata[iterations*bsize:sz]...))
	revokedCerts = append(revokedCerts, pkix.RevokedCertificate{SerialNumber: n, RevocationTime: now, Extensions: []pkix.Extension{extSubKeyId}})
	//Create our CRL file
	crlBytes, _ := cert.CreateCRL(rand.Reader, priv, revokedCerts, now, expiry)
	//Write it to disk
	ioutil.WriteFile("test.crl", crlBytes, 0644)

}
