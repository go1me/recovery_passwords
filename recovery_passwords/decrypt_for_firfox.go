package recovery_passwords

//https://github.com/moonD4rk/HackBrowserData
import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"log"

	"golang.org/x/crypto/pbkdf2"
)

type NssPBE struct {
	SequenceA
	Encrypted []byte
}

type MetaPBE struct {
	SequenceA
	Encrypted []byte
}
type SequenceA struct {
	PKCS5PBES2 asn1.ObjectIdentifier
	SequenceB
}
type SequenceB struct {
	SequenceC
	SequenceD
}

type SequenceC struct {
	PKCS5PBKDF2 asn1.ObjectIdentifier
	SequenceE
}

type SequenceD struct {
	AES256CBC asn1.ObjectIdentifier
	IV        []byte
}

type SequenceE struct {
	EntrySalt      []byte
	IterationCount int
	KeySize        int
	SequenceF
}

type SequenceF struct {
	HMACWithSHA256 asn1.ObjectIdentifier
}

func DecodeMeta(decodeItem []byte) (pbe MetaPBE, err error) {
	_, err = asn1.Unmarshal(decodeItem, &pbe)
	if err != nil {
		log.Println(err)
		return
	}
	return
}

func DecodeNss(nssA11Bytes []byte) (pbe NssPBE, err error) {
	log.Println(hex.EncodeToString(nssA11Bytes))
	_, err = asn1.Unmarshal(nssA11Bytes, &pbe)
	if err != nil {
		log.Println(err)
		return
	}
	return
}

func Meta(globalSalt, masterPwd []byte, pbe MetaPBE) ([]byte, error) {
	return decryptMeta(globalSalt, masterPwd, pbe.IV, pbe.EntrySalt, pbe.Encrypted, pbe.IterationCount, pbe.KeySize)
}

func Nss(globalSalt, masterPwd []byte, pbe NssPBE) ([]byte, error) {
	return decryptMeta(globalSalt, masterPwd, pbe.IV, pbe.EntrySalt, pbe.Encrypted, pbe.IterationCount, pbe.KeySize)
}

func decryptMeta(globalSalt, masterPwd, nssIv, entrySalt, encrypted []byte, iter, keySize int) ([]byte, error) {
	k := sha1.Sum(globalSalt)
	log.Println(hex.EncodeToString(k[:]))
	key := pbkdf2.Key(k[:], entrySalt, iter, keySize, sha256.New)
	log.Println(hex.EncodeToString(key))
	i, err := hex.DecodeString("040e")
	if err != nil {
		log.Println(err)
	}
	// @https://hg.mozilla.org/projects/nss/rev/fc636973ad06392d11597620b602779b4af312f6#l6.49
	iv := append(i, nssIv...)
	dst, err := aes128CBCDecrypt(key, iv, encrypted)
	if err != nil {
		log.Println(err)
	}
	return dst, err
}

var (
	errSecurityKeyIsEmpty = errors.New("input [security find-generic-password -wa 'Chrome'] in terminal")
	errPasswordIsEmpty    = errors.New("password is empty")
	errDecryptFailed      = errors.New("decrypt failed, password is empty")
)

func aes128CBCDecrypt(key, iv, encryptPass []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	dst := make([]byte, len(encryptPass))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(dst, encryptPass)
	dst = PKCS5UnPadding(dst)
	return dst, nil
}

func PKCS5UnPadding(src []byte) []byte {
	length := len(src)
	unpad := int(src[length-1])
	return src[:(length - unpad)]
}

func Des3Decrypt(key, iv []byte, src []byte) ([]byte, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		log.Println(err)
		return nil, err
	}
	blockMode := cipher.NewCBCDecrypter(block, iv)
	sq := make([]byte, len(src))
	blockMode.CryptBlocks(sq, src)
	return sq, nil
}

func PaddingZero(s []byte, l int) []byte {
	h := l - len(s)
	if h <= 0 {
		return s
	} else {
		for i := len(s); i < l; i++ {
			s = append(s, 0)
		}
		return s
	}
}

type LoginPBE struct {
	CipherText []byte
	SequenceLogin
	Encrypted []byte
}

type SequenceLogin struct {
	asn1.ObjectIdentifier
	Iv []byte
}

func DecodeLogin(decodeItem []byte) (pbe LoginPBE, err error) {
	_, err = asn1.Unmarshal(decodeItem, &pbe)
	if err != nil {
		log.Println(err)
		return
	}
	return pbe, nil
}
