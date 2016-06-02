package goproxy

import "crypto/tls"

var UserCertificates map[string]tls.Certificate
var tlsClientSkipVerify = &tls.Config{InsecureSkipVerify: true}

func init() {
	UserCertificates = make(map[string]tls.Certificate)
}

var defaultTLSConfig = &tls.Config{
	InsecureSkipVerify: true,
}

func AddUserCertificate(host string, certFile string, keyFile string) error {
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}
	UserCertificates[host] = pair
	return nil
}
