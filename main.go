package main

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"os"
	"strings"

	"acovia.net/record"
)

var (
	ncmFileName string
)
func unPadding(data []byte) []byte {
	dataLength := len(data)
	padLength := int(data[dataLength-1])
	return data[:dataLength - padLength]
}

func main() {

	flag.Parse()

	if len(flag.Arg(0)) != 0 {
		ncmFileName = flag.Arg(0)
	} else {
		os.Exit(1)
	}

	coreKey, metaKey, err := getKnownKey()
	record.CheckErr(err, "(get known key) %v", err)

	ncmFile, err := os.Open(ncmFileName)
	record.CheckErr(err, "(open file) %v", err)

	checkHeader(ncmFile)
	record.Info("file header validation passed")

	audioKey, err := getAudioKey(ncmFile, coreKey)
	record.CheckErr(err, "(get audio key) %v", err)
	record.Info("audio key: %v", string(audioKey))

	metaData, err := getMetaData(ncmFile, metaKey)
	record.CheckErr(err, "(get meta data) %v", err)
	record.Info("meta data: %v", string(metaData))

	_, err = getImgData(ncmFile)
	record.CheckErr(err, "(get image data) %v", err)

	audioData, err := getAudio(ncmFile, audioKey)
	record.CheckErr(err, "(get audio data) %v", err)

	outputFileName := strings.Replace(ncmFileName, ".ncm", ".wav", 1)
	os.WriteFile(outputFileName, audioData, 0700)

}

func decipher(data []byte, key []byte) ([]byte, error) {

	block, err := aes.NewCipher(key)

	if err != nil {
		return nil, err
	}

	plaintext := make([]byte,len(data))

	for n := 0; n + block.BlockSize() <= len(data); n += block.BlockSize() {
		block.Decrypt(plaintext[n:n+block.BlockSize()], data[n:n+block.BlockSize()])
	}

	return unPadding(plaintext), nil
}

func xorBytes(data []byte, refByte uint8) {
	for i := range data {
		data[i] ^= refByte
	}
}

func checkHeader(ncmFile *os.File) {

	header := make([]byte, 8)

	_, err := ncmFile.Read(header)
	record.CheckErr(err, "%v", err)

	if string(header) != "CTENFDAM" {
		record.Error("not a valid ncm file")
	}

}

func getAudioKey(ncmFile *os.File, coreKey []byte) ([]byte, error) {

	_, err := ncmFile.Read(make([]byte, 2))
	if err != nil {
		return nil, err
	}

	keyLengthData := make([]byte, 4)
	ncmFile.Read(keyLengthData)

	keyLength := binary.LittleEndian.Uint32(keyLengthData)

	enkeyData := make([]byte, keyLength)

	_, err = ncmFile.Read(enkeyData)
	if err != nil {
		return nil, err
	}

	xorBytes(enkeyData, 0x64)

	keyData, err := decipher(enkeyData, coreKey)
	if err != nil {
		return nil, err
	}

	key := bytes.Replace(keyData, []byte("neteasecloudmusic"), []byte{}, 1)

	return key, nil
}

func getKnownKey() ([]byte, []byte, error) {

	coreKey, err := hex.DecodeString("687a4852416d736f356b496e62617857")
	if err != nil {
		return nil, nil, err
	}

	metaKey, err := hex.DecodeString("2331346c6a6b5f215c5d2630553c2728")
	if err != nil {
		return nil, nil, err
	}

	return coreKey, metaKey, nil

}

func getMetaData(ncmFile *os.File, metaKey []byte) ([]byte, error) {

	metaDataLengthData := make([]byte, 4)
	_, err := ncmFile.Read(metaDataLengthData)
	if err != nil {
		return nil, err
	}

	metaDataLength := binary.LittleEndian.Uint32(metaDataLengthData)
	record.Debug("%v", metaDataLength)

	enMetaData := make([]byte, metaDataLength)
	_, err = ncmFile.Read(enMetaData)
	if err != nil {
		return nil, err
	}

	xorBytes(enMetaData, 0x63)

	metaDataBase64 := bytes.Replace(enMetaData, []byte("163 key(Don't modify):"), []byte{}, 1)

	cipherMetaData := make([]byte, base64.StdEncoding.DecodedLen(len(metaDataBase64)))

	_, err = base64.StdEncoding.Decode(cipherMetaData, metaDataBase64)
	if err != nil {
		return nil, err
	}

	metaData, err := decipher(cipherMetaData, metaKey)
	if err != nil {
		return nil, err
	}

	return metaData, nil

}

func getImgData(ncmFile *os.File) ([]byte, error) {

	cbc := make([]byte, 4)

	_, err := ncmFile.Read(cbc)
	if err != nil {
		return nil, err
	}

	_, err = ncmFile.Read(make([]byte, 5))
	if err != nil {
		return nil, err
	}

	imgLengthData := make([]byte, 4)
	_, err = ncmFile.Read(imgLengthData)
	if err != nil {
		return nil, err
	}

	imgLength := binary.LittleEndian.Uint32(imgLengthData)

	imgData := make([]byte, imgLength)
	_, err = ncmFile.Read(imgData)
	if err != nil {
		return nil, err
	}

	return imgData, nil

}

func getAudio(ncmFile *os.File, audioKey []byte) ([]byte, error){

	box := buildKeyBox(audioKey)
	n := 32768
	var writer bytes.Buffer

	var tb = make([]byte, n)
	for {
		if _, err := ncmFile.Read(tb); err != nil {
			break
		}

		for i := 0; i < n; i++ {
			j := byte((i + 1) & 0xff)
			tb[i] ^= box[(box[j]+box[(box[j]+j)&0xff])&0xff]
		}

		writer.Write(tb)
	}

	return writer.Bytes(), nil

}

func buildKeyBox(key []byte) []byte {
	box := make([]byte, 256)
	for i := 0; i < 256; i++ {
		box[i] = byte(i)
	}
	keyLen := byte(len(key))
	var c, lastByte, keyOffset byte
	for i := 0; i < 256; i++ {
		c = (box[i] + lastByte + key[keyOffset]) & 0xff
		keyOffset++
		if keyOffset >= keyLen {
			keyOffset = 0
		}
		box[i], box[c] = box[c], box[i]
		lastByte = c
	}
	return box
}