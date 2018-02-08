/*
Code for demonstrating recovering a file hidding inside a CRL using main.go.
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
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
)

var bsize = 500

func main() {
	fdata, _ := ioutil.ReadFile("test.crl")
	//Parse the CRL file
	parsedCRL, err := x509.ParseDERCRL(fdata)
	if err != nil {
		log.Fatalf("error reparsing CRL: %s", err)
	}
	//The file will be appended into blob
	blob := []byte{}
	//Get the list of certificate revocations
	revokedCerts := parsedCRL.TBSCertList.RevokedCertificates
	for i := 0; i < len(revokedCerts); i++ {
		//Each serial number has an extra '\x01' prepended to it so we need to strip that
		blob = append(blob, revokedCerts[i].SerialNumber.Bytes()[1:]...)
		//Check if there's an extension
		if len(revokedCerts[i].Extensions) > 0 {
			//If so we're going to assume it's a hash for the data received thus far
			h := sha256.New()
			h.Write(blob)
			if bytes.Compare(h.Sum(nil), revokedCerts[i].Extensions[0].Value) == 0 {
				fmt.Println("Hash matches")
			}
		}
	}
	//Write the recovered file to disk
	ioutil.WriteFile("test.recover", blob, 0644)

}
