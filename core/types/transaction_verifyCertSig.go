//@Time  : 2018/3/14 11:34
//@Author: lyszhang
package types

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"errors"
	"os/exec"
	"os"
	"strings"
	"path/filepath"
	"runtime"
	"os/user"
	"time"
)

func parseTcaRsa() (rcaCert *x509.Certificate,txCert *x509.Certificate) {
	//解析tca证书
	tcaFile, err1 := ioutil.ReadFile("tca.crt")
	if err1 != nil {
		fmt.Println("ReadFile err:", err1)
		return
	}

	tcaBlock, _:= pem.Decode(tcaFile)
	if tcaBlock == nil {
		fmt.Println("ecaFile error")
		return
	}

	tcaCert, err := x509.ParseCertificate(tcaBlock.Bytes)
	if err != nil {
		fmt.Println("ParseCertificate err:", err)
		return
	}

	//解析tx证书
	txFile, err := ioutil.ReadFile("tx.crt")
	if err != nil {
		fmt.Println("ReadFile err:", err)
		return
	}

	txBlock, _:= pem.Decode(txFile)
	if txBlock == nil {
		fmt.Println("ecaFile error")
		return
	}

	txCert, err= x509.ParseCertificate(txBlock.Bytes)
	if err != nil {
		fmt.Println("ParseCertificate err:", err)
		return
	}
	return tcaCert,txCert
}

func parseEcdsaByte (txData []byte) (cert *x509.Certificate) {
	//解析证书
	txBlock, _:= pem.Decode(txData)
	if txBlock == nil {
		fmt.Println("TcertFile error")
		return
	}

	cert, err := x509.ParseCertificate(txBlock.Bytes)
	if err != nil {
		fmt.Println("Tcert ecdsa byte ParseCertificate err:", err)
		return
	}
	return cert
}

func getCurrentPath() (string) {
	file, err := exec.LookPath(os.Args[0])
	if err != nil {
		return ""
	}
	path, err := filepath.Abs(file)
	if err != nil {
		return ""
	}
	i := strings.LastIndex(path, "/")
	if i < 0 {
		i = strings.LastIndex(path, "\\")
	}
	if i < 0 {
		return ""
	}
	return string(path[0 : i+1])
}

// DefaultDataDir is the default data directory to use for the databases and other
// persistence requirements.
func DefaultDataDir() string {
	// Try to place the data folder in the user's home dir
	home := homeDir()
	if home != "" {
		if runtime.GOOS == "darwin" {
			return filepath.Join(home, "Library", "Ethereum")
		} else if runtime.GOOS == "windows" {
			return filepath.Join(home, "AppData", "Roaming", "Ethereum")
		} else {
			return filepath.Join(home, ".ethereum")
		}
	}
	// As we cannot guess a stable location, return empty and handle later
	return ""
}

func homeDir() string {
	if home := os.Getenv("HOME"); home != "" {
		return home
	}
	if usr, err := user.Current(); err == nil {
		return usr.HomeDir
	}
	return ""
}


func readTcaEcdsa() (rcaCert *x509.Certificate) {
	//解析tca证书
	//path := getCurrentPath()
	//fmt.Println("The current path is:", path)

	tcaCrtPath := DefaultDataDir() + "/geth/keystore/tca.crt"
	tcaFile, err1 := ioutil.ReadFile(tcaCrtPath)
	if err1 != nil {
		fmt.Println("ReadFile err:", err1)
		return
	}

	tcaBlock, _:= pem.Decode(tcaFile)
	if tcaBlock == nil {
		fmt.Println("TcaFile error")
		return
	}

	tcaCert, err2 := x509.ParseCertificate(tcaBlock.Bytes)
	if err2 != nil {
		fmt.Println("Tca ecdsa ParseCertificate err:", err2)
		return
	}

	return tcaCert
}

func checkCert (txCertData []byte, sigCert []byte, addrFrom string) error {

	var tcaCert *x509.Certificate
	var txCert *x509.Certificate

	tcaCert = readTcaEcdsa()
	if tcaCert == nil {
		return errors.New("tcaCert missing")
	}

	txCert = parseEcdsaByte(txCertData)
	if txCert == nil {
		return errors.New("txcert error")
	}
	fmt.Println("checkCert")

	//解析时间
	startTime := txCert.NotBefore
	endTime := txCert.NotAfter
	if time.Now().Before(startTime) || time.Now().After(endTime) {
		fmt.Println("The certificate is out of date, startTime:",startTime, "endTime", endTime)
		return errors.New("The certificate is out of date")
	}

	//解析地址
	/*
	addr := txCert.EmailAddresses[0]
	if len(addr) < 42 {
		fmt.Println("The authentication address is none!")
		return errors.New("The authentication address is none!")
	}

	if !strings.EqualFold(addrFrom, addr[:42]) {
		fmt.Println("The tx transaction's addr is:", addr[:42], "from", addrFrom)
		return errors.New("The tx source address doesn't match the address in tcert")
	}
	*/
	//验证签名
	err := txCert.CheckSignatureFrom(tcaCert)
	fmt.Println("check txCert signature: ", err == nil)
	return err
}




