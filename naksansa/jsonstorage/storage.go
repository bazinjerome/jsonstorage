package jsonstorage

//JSONstorage is an encrypted storage
//the storage is a json array

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/json"
	"golang.org/x/crypto/pbkdf2"
	"io/ioutil"
	"os"
)

func StoreValueForKey(filePath, password, salt, hmacSalt, key, value string) error {

	storage := &JsonStorage{filePath,
		password,
		salt,
		hmacSalt,
	}

	return storage.storeString(key, value)
}

func GetValueForkey(filePath, password, salt, hmacSalt, key string) (string, error) {

	storage := &JsonStorage{filePath,
		password,
		salt,
		hmacSalt,
	}

	result, error := storage.getString(key)

	if error != nil {
		return "",error
	}

	return result, error
}

type JsonStorage struct {
	filePath,
	password,
	salt,
	hmacSalt string
}

const jsonStream = `{}`

func (jsonStorage *JsonStorage) storeString(key, value string) error {
	//if the file does not exist
	if _, err := os.Stat(jsonStorage.filePath); os.IsNotExist(err) {
		jsonStreamBytes := []byte(jsonStream)
		writeFileStorage(jsonStreamBytes, jsonStorage.filePath, jsonStorage.password, jsonStorage.salt, jsonStorage.hmacSalt)
	}

	//decrypt
	decrypted, readError := readByteFromStorage(jsonStorage.filePath, jsonStorage.password, jsonStorage.salt, jsonStorage.hmacSalt)

	if readError != nil {
		return readError
	}

	var values map[string]string
	unMarshallError := json.Unmarshal([]byte(decrypted), &values)
	if unMarshallError != nil {
		return unMarshallError
	}
	//edit
	values[key] = value

	//format
	jsonStreamBytes, marshalError := json.Marshal(values)
	if marshalError != nil {
		return marshalError
	}

	//save
	return writeFileStorage(jsonStreamBytes, jsonStorage.filePath, jsonStorage.password, jsonStorage.salt, jsonStorage.hmacSalt)

}

func (jsonStorage *JsonStorage) getString(key string) (string, error) {
	//decrypt
	decrypted, storageError := readByteFromStorage(jsonStorage.filePath, jsonStorage.password, jsonStorage.salt, jsonStorage.hmacSalt)

	if storageError != nil {
		return "", storageError
	}

	var values map[string]string
	unMarshallError := json.Unmarshal([]byte(decrypted), &values)

	if unMarshallError != nil {
		return "", unMarshallError
	}

	return values[key], nil
}

func writeFileStorage(jsonBytes []byte, filePath, password, salt, hmacSalt string) error {
	cipherText, encError := boxFileStorage(jsonBytes, password, salt, hmacSalt)

	if encError != nil {
		return encError
	}

	//store ciphertext;
	writeError := ioutil.WriteFile(filePath, cipherText, 0644)
	if writeError != nil {
		return writeError
	}
	return nil
}

func readByteFromStorage(filePath, password, salt, hmacSalt string) ([]byte, error) {

	cipherText2, readError := ioutil.ReadFile(filePath)
	if readError != nil {
		return nil, readError
	}
	decrypted, deencError := unboxStorage(cipherText2, password, salt, hmacSalt)

	if deencError != nil {
		return nil, deencError
	}

	return decrypted, readError
}

func boxFileStorage(message []byte, password, salt, hmacSalt string) ([]byte, error) {
	encrypter, error := getAESEncrypter(password, salt)

	if error != nil {
		return nil, error
	}

	cipherText := encryptBytes(message, encrypter)
	hmacValue := hmacBytes(cipherText, hmacSalt)
	cipherText = append(hmacValue[:], cipherText[:]...)
	return cipherText, nil
}

func unboxStorage(cipherText []byte, password, salt, hmacSalt string) ([]byte, error) {
	decrypter, error := getAESDecrypter(password, salt)

	if error != nil {
		return nil, error
	}

	hmacv2 := hmacBytes(cipherText[32:], hmacSalt)
	hmacValue := cipherText[:32]

	//non altered storage ?
	if hmac.Equal(hmacValue, hmacv2) {
		decrypted := decryptBytes(cipherText[32:], decrypter)
		return decrypted, nil
	}

	return nil, nil
}

func hmacBytes(input []byte, salt string) []byte {
	hmac := hmac.New(sha256.New, []byte(salt))
	hmac.Write(input)
	return hmac.Sum(nil)
}

func decryptBytes(inputs []byte, decrypter cipher.BlockMode) []byte {
	var decryptedOutput []byte = make([]byte, len(inputs))
	decrypter.CryptBlocks(decryptedOutput, inputs)
	return unPaddBytewithBlock(decryptedOutput)
}

func encryptBytes(inputs []byte, encrypter cipher.BlockMode) []byte {
	//padd byte
	paddedBytes := paddByteWithBlock(inputs, aes.BlockSize)

	encryptedOutput := make([]byte, len(paddedBytes))

	encrypter.CryptBlocks(encryptedOutput, paddedBytes)
	return encryptedOutput
}

func getAESEncrypter(password, salt string) (cipher.BlockMode, error) {

	// 32 byte key => aes 256
	dk := pbkdf2.Key([]byte(password), []byte(salt), 4096, 32, sha1.New)

	// pkbdf2 iv
	iv := pbkdf2.Key([]byte(password), []byte(salt), 4096, 16, sha1.New)

	//key aes 256
	aesKey, error := aes.NewCipher(dk)
	if error != nil {
		return nil, error
	}

	//encrypter
	return cipher.NewCBCEncrypter(aesKey, iv), nil
}

func getAESDecrypter(password, salt string) (cipher.BlockMode, error) {

	// 32 byte key => aes 256
	dk := pbkdf2.Key([]byte(password), []byte(salt), 4096, 32, sha1.New)

	// pkbdf2 iv
	iv := pbkdf2.Key([]byte(password), []byte(salt), 4096, 16, sha1.New)

	//key aes 256
	aesKey, error := aes.NewCipher(dk)
	if error != nil {
		return nil, error
	}

	//decrypter
	return cipher.NewCBCDecrypter(aesKey, iv), nil
}

func paddByteWithBlock(jsonStreamBytes []byte, blockSize int) []byte {
	padding := 0
	if len(jsonStreamBytes)%blockSize != 0 {
		padding = blockSize - len(jsonStreamBytes)%blockSize
	}
	paddedtext := bytes.Repeat([]byte{byte(0)}, padding)
	return append(jsonStreamBytes, paddedtext...)
}

func unPaddBytewithBlock(padded []byte) []byte {
	padded = bytes.Trim(padded, "\x00")
	return padded
}
