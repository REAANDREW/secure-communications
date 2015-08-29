package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
)

/*

#include <stdlib.h>
//************
// SO THIS WORKS NOW but I have had to hardcode the crypto library as I cannot
// seem to get ENVIRONMENT variables to pass in which are quoted
//************
//#cgo CFLAGS: -std=gnu11  -D__XMLSEC_FUNCTION__=__FUNCTION__ -DXMLSEC_NO_SIZE_T -DXMLSEC_NO_GOST=1 -DXMLSEC_NO_XKMS=1 -DXMLSEC_DL_LIBLTDL=1 -I/usr/local/include/xmlsec1 -I/usr/include/libxml2 -DXMLSEC_CRYPTO_DYNAMIC_LOADING=1 -DXMLSEC_CRYPTO=openssl
#cgo CFLAGS: -std=gnu11  -D__XMLSEC_FUNCTION__=__FUNCTION__ -DXMLSEC_NO_SIZE_T -DXMLSEC_NO_GOST=1 -DXMLSEC_NO_XKMS=1 -DXMLSEC_NO_CRYPTO_DYNAMIC_LOADING=1 -I/usr/include/xmlsec1  -DXMLSEC_OPENSSL_100=1 -DXMLSEC_CRYPTO_OPENSSL=1 -I/usr/include/libxml2
//#cgo LDFLAGS: -L/usr/local/lib -lxmlsec1 -lltdl -lxslt  -lxml2 -lssl -lcrypto
#cgo LDFLAGS: -lxmlsec1-openssl -lxmlsec1 -lssl -lcrypto -lxslt  -lxml2

#include "signio.h"

//https://github.com/apache/qpid-proton/tree/master/examples/go

*/
import "C"
import "unsafe"

func initializeXmlSec(signatureManager *C.SignatureManager) {
	returnCode := C.init(signatureManager)
	if returnCode != 0 {
		panic("xmlsec initialization failed")
	}
}

func shutdownXmlSec(signatureManager *C.SignatureManager) {
	C.shutdown(signatureManager)
}

func createCertManager(certPaths []string) C.xmlSecKeysMngrPtr {
	paths := make([]*C.char, len(certPaths))
	for index, item := range certPaths {
		certPath, _ := filepath.Abs(item)
		paths[index] = C.CString(certPath)
	}
	return C.load_trusted_certs(&paths[0], C.int(len(certPaths)))
}

func verify(xml string, certManager C.xmlSecKeysMngrPtr) bool {
	cXml := C.CString(xml)

	defer C.free(unsafe.Pointer(cXml))
	verification := C.verify_file_contents(certManager, cXml)
	fmt.Println("verification code %v", verification)
	if verification == 0 {
		return true
	} else {
		return false
	}
}

func sign(xml string, keyPath string, certPath string) string {
	var output *C.char

	keyPath, _ = filepath.Abs(keyPath)
	certPath, _ = filepath.Abs(certPath)

	cXml := C.CString(xml)
	cKeyPath := C.CString(keyPath)
	cCertPath := C.CString(certPath)

	defer C.free(unsafe.Pointer(output))
	defer C.free(unsafe.Pointer(cXml))
	defer C.free(unsafe.Pointer(cKeyPath))
	defer C.free(unsafe.Pointer(cCertPath))

	//This needs to be the part where the output is transferred by refrence argument
	code := C.sign_file_contents(cXml, cKeyPath, cCertPath, &output)
	//code := C.sign_file_contents(cXml, cKeyPath, cCertPath, &output, &size)
	if code != 0 {
		panic("Signing the data failed")
	}
	return C.GoString(output)
}

func main() {

	sigManager := C.CreateSignatureManager()
	initializeXmlSec(sigManager)
	fileBytes, _ := ioutil.ReadFile("./data/example.xml")
	output := sign(string(fileBytes), "./CA/client.key", "./CA/client.pem")
	outputPath, _ := filepath.Abs("./output.xml")
	ioutil.WriteFile(outputPath, []byte(output), 0644)

	certs := []string{"./CA/client.pem", "./CA/cacert.pem"}
	certManager := createCertManager(certs)
	verify(output, certManager)
	//fmt.Printf("Size of the signature %d \n output: %v \n validated %v\n", len(output), output, result)
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for sig := range c {
			fmt.Printf("Closing Down %v\n", sig)
			shutdownXmlSec(sigManager)
			close(c)
			os.Exit(0)
		}
	}()

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello cert")
	})

	serverCaCert, server_err := ioutil.ReadFile("./CA/cacert.pem")
	if server_err != nil {
		panic(server_err)
	}
	serverCaCertPool := x509.NewCertPool()
	serverCaCertPool.AppendCertsFromPEM(serverCaCert)

	server := &http.Server{
		Addr: ":8090",
		TLSConfig: &tls.Config{
			ClientAuth: tls.RequireAndVerifyClientCert,
			ServerName: "secure.acme.com",
			RootCAs:    serverCaCertPool,
			ClientCAs:  serverCaCertPool,
		},
	}

	fmt.Println("Setting up")
	fmt.Println(fmt.Printf("%v", server.ListenAndServeTLS("./config/server.pem", "./config/server.key")))
	fmt.Println("Listening")
}

type SecureServer struct {
	ServerName    string
	RootCAPaths   []string
	ClientCAPaths []string
	ServerCert    string
	ServerKey     string
}
