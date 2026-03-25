//go:build fips

package kem

import "fmt"

func NewKyber512Provider() (KyberProvider, error) {
	return nil, fmt.Errorf("kyber is disabled in FIPS builds")
}

func NewKyber768Provider() (KyberProvider, error) {
	return nil, fmt.Errorf("kyber is disabled in FIPS builds")
}

func NewKyber1024Provider() (KyberProvider, error) {
	return nil, fmt.Errorf("kyber is disabled in FIPS builds")
}
