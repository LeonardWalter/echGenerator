package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"

	"golang.org/x/crypto/cryptobyte"
)

const (
	extensionEncryptedClientHello = 0xfe0d
	AEAD_AES_128_GCM              = 0x0001
	AEAD_AES_256_GCM              = 0x0002
	AEAD_ChaCha20Poly1305         = 0x0003

	KDF_HKDF_SHA256          = 0x0001
	DHKEM_X25519_HKDF_SHA256 = 0x0020
)

var sortedSupportedAEADs = []uint16{
	AEAD_AES_128_GCM,
	AEAD_AES_256_GCM,
	AEAD_ChaCha20Poly1305,
}

func main() {
	serverName := flag.String("s", "", "Server name")
	idFlag := flag.Int("i", -1, "ECH ID (uint8)")
	outputFile := flag.String("o", "", "Output file")
	helpFlag := flag.Bool("h", false, "Show help")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [flags]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if *helpFlag || (len(os.Args) == 1) {
		flag.Usage()
		os.Exit(0)
	}

	if *serverName == "" {
		flag.Usage()
		log.Fatal("Server name is required")
	}

	var id uint8
	if *idFlag == -1 {
		randomID, err := rand.Int(rand.Reader, big.NewInt(256))
		if err != nil {
			log.Fatalf("Failed to generate random ID: %v", err)
		}
		id = uint8(randomID.Int64())
	} else {
		if *idFlag > 255 || *idFlag < 0 {
			log.Fatalf("ID must be a uint8 (0-255), got %d", *idFlag)
		}
		id = uint8(*idFlag)
	}

	if *outputFile == "" {
		*outputFile = *serverName + ".pem.ech"
	}

	generateKeyFile(id, *serverName, *outputFile)
}

// Creates an ECH config directly, without the extension header
func createECHConfig(id uint8, pubKey []byte, publicName string, maxNameLen uint8) []byte {
	builder := cryptobyte.NewBuilder(nil)
	builder.AddUint16(extensionEncryptedClientHello)
	builder.AddUint16LengthPrefixed(func(builder *cryptobyte.Builder) {
		builder.AddUint8(id)
		builder.AddUint16(DHKEM_X25519_HKDF_SHA256) // The only DHKEM we support
		builder.AddUint16LengthPrefixed(func(builder *cryptobyte.Builder) {
			builder.AddBytes(pubKey)
		})
		builder.AddUint16LengthPrefixed(func(builder *cryptobyte.Builder) {
			for _, aeadID := range sortedSupportedAEADs {
				builder.AddUint16(KDF_HKDF_SHA256) // The only KDF we support
				builder.AddUint16(aeadID)
			}
		})
		builder.AddUint8(maxNameLen)
		builder.AddUint8LengthPrefixed(func(builder *cryptobyte.Builder) {
			builder.AddBytes([]byte(publicName))
		})
		builder.AddUint16(0) // extensions
	})

	return builder.BytesOrPanic()
}

func GenerateECHpem(id uint8, serverName string) []byte {
	echKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate ECH key: %v", err)
	}

	// Convert the private key to PKCS#8 format
	pkcs8Key, err := x509.MarshalPKCS8PrivateKey(echKey)
	if err != nil {
		log.Fatalf("Failed to encode key to PKCS#8: %v", err)
	}

	echConfig := createECHConfig(id, echKey.PublicKey().Bytes(), serverName, 32)

	builder := cryptobyte.NewBuilder(nil)
	builder.AddUint16LengthPrefixed(func(builder *cryptobyte.Builder) {
		builder.AddBytes(echConfig)
	})
	echConfigList := builder.BytesOrPanic()

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkcs8Key,
	})

	// Encode the ECH config list in PEM format
	echConfigListBase64 := base64.StdEncoding.EncodeToString(echConfigList)
	echConfigPEM := fmt.Sprintf("-----BEGIN ECHCONFIG-----\n%s\n-----END ECHCONFIG-----\n",
		echConfigListBase64)

	return bytes.Join([][]byte{privateKeyPEM, []byte(echConfigPEM)}, nil)
}

func generateKeyFile(id uint8, serverName string, outputFile string) {
	output := GenerateECHpem(id, serverName)
	err := os.WriteFile(outputFile, []byte(output), 0644)
	if err != nil {
		log.Fatalf("Failed to write to file %s: %v", outputFile, err)
	}

	fmt.Printf("ECH key and config written to %s\n", outputFile)
}
