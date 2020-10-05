package recovery_passwords
import(
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
)

// htttps://github.com/cckuailong/HackChrome/blob/master/utils/cipher.go
func AesGCMDecrypt(crypted,key,nounce []byte)([]byte,error){
	block,err := aes.NewCipher(key)
	if err != nil{
		return nil,err
	}
	blockMode,_ := cipher.NewGCM(block)
	origData,err := blockMode.Open(nil,nounce,crypted,nil)
	if err != nil{
		return nil,err
	}
	return origData,nil
}

//https://studygolang.com/articles/14251

//使用PKCS7进行填充，IOS也是7
func PKCS7UnPadding(origData []byte)([]byte){
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length-unpadding)]
}

func AesCBCDncrypt(encryptData,key,iv []byte)([]byte,error){
	block,err := aes.NewCipher(key)
	if err != nil{
		panic(err)
	}
	blocksize := block.BlockSize()
	if len(encryptData) < blocksize{
		panic("cipertext too short")
	}
	if len(encryptData)%blocksize != 0{
		panic("ciphertext is not a multiple of the block size")
	}
	mode := cipher.NewCBCDecrypter(block,iv)
	mode.CryptBlocks(encryptData,encryptData)
	encryptData = PKCS7UnPadding(encryptData)
	return encryptData,nil
}

func AESDncrypt(rawData string,key []byte,iv []byte)(string,error){
	data,err := base64.StdEncoding.DecodeString(rawData)
	if err != nil{
		return "",err
	}
	dnData,err := AesCBCDncrypt(data,key,iv)
	if err != nil{
		return "", err
	}
	return string(dnData), nil
}