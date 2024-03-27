package ppk

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"

	"golang.org/x/crypto/ssh"
)

const (
	lineLength = 64
)

func GeneratePPK(comment string) (pubKey, ppk string, err error) {
	encryption := "none"
	keyType := "ssh-rsa"

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}

	// Public-Lines: N lines containing a base64 encoded version of the public
	// part of the key. This is encoded as the standard SSH-2 public key blob.
	// for RSA it will be:
	// - "ssh-rsa"
	// - exponent
	// - modulus
	pub, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		return "", "", err
	}
	pubBlob := pub.Marshal()
	pubLines := splitString(base64.StdEncoding.EncodeToString(pubBlob), lineLength)

	ppk = fmt.Sprintf("PuTTY-User-Key-File-2: %s\nEncryption: %s\nComment: %s\n", keyType, encryption, comment)
	ppk += fmt.Sprintf("Public-Lines: %d\n", len(pubLines))
	for _, line := range pubLines {
		ppk += fmt.Sprintf("%s\n", line)
	}

	// Private-Lines: N lines containing the (potentially encrypted) private
	// part of the key. For the key-type "ssh-rsa", this will be composed of
	// - private_exponent
	// - P (larger prime)
	// - Q (smaller prime)
	// - IQMP (inverse of Q modulo P)
	// all the above values are mpint (read more: https://datatracker.ietf.org/doc/html/rfc4251)
	var privBlob []byte
	P, Q := privateKey.Primes[1], privateKey.Primes[0]
	privBlob = append(privBlob, putPrefixed(privateKey.D.Bytes())...)
	privBlob = append(privBlob, putPrefixed(P.Bytes())...)
	privBlob = append(privBlob, putPrefixed(Q.Bytes())...)
	privBlob = append(privBlob, putPrefixed(new(big.Int).ModInverse(Q, P).Bytes())...)

	privLines := splitString(base64.StdEncoding.EncodeToString(privBlob), lineLength)
	ppk += fmt.Sprintf("Private-Lines: %d\n", len(privLines))
	for _, line := range privLines {
		ppk += fmt.Sprintf("%s\n", line)
	}

	// Private-MAC: hex representation of a HMAC-SHA-1 of
	// - name of algorithm
	// - encryption type
	// - comment
	// - public-blob
	// - private-plaintext (the plaintext version of the private part, including the final padding)
	var macData []byte
	macData = append(macData, putPrefixed([]byte(keyType))...)
	macData = append(macData, putPrefixed([]byte(encryption))...)
	macData = append(macData, putPrefixed([]byte(comment))...)
	macData = append(macData, putPrefixed(pubBlob)...)
	macData = append(macData, putPrefixed(privBlob)...)

	mac := getMAC(macData)
	ppk += fmt.Sprintf("Private-MAC: %s\n", hex.EncodeToString(mac))

	pubKey, err = getPublicKey(comment, privateKey)

	return pubKey, ppk, err
}

func getPublicKey(comment string, privateKey *rsa.PrivateKey) (string, error) {
	pub, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s %s", ssh.MarshalAuthorizedKey(pub), comment), nil
}

func getMAC(bytes []byte) []byte {
	h1 := sha1.New()
	h1.Write([]byte("putty-private-key-file-mac-key"))
	macKey := h1.Sum(nil)

	h2 := hmac.New(sha1.New, macKey)
	h2.Write(bytes)
	return h2.Sum(nil)
}

func splitString(s string, n int) []string {
	var res []string

	for i := 0; i < len(s); i += n {
		end := i + n
		if end > len(s) {
			end = len(s)
		}
		res = append(res, s[i:end])
	}

	return res
}

func putPrefixed(s []byte) []byte {
	var res []byte

	// https://datatracker.ietf.org/doc/html/rfc4251 (mpint)
	if s[0]&0x80 > 0 {
		s = append([]byte{0}, s...)
	}

	length := make([]byte, 4)
	binary.BigEndian.PutUint32(length, uint32(len(s)))

	res = append(res, length...)
	res = append(res, s...)

	return res
}
