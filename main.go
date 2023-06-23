package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/ssh"
)

type KeyPaths struct {
	PrivateKeyPath string `json:"private_key_path"`
	PublicKeyPath  string `json:"public_key_path"`
	KeyName        string `json:"key_name"`
	PrivateKey     string `json:"private_key"`
	PublicKey      string `json:"public_key"`
	Suffix         string `json:"suffix"`
	KeyType        string `json:"key_type"`
	Created        int64  `json:"created"`
}

func GenerateRandomString(length int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		panic(err) // Error handling should be added in your production code
	}
	for i := range b {
		b[i] = letters[int(b[i])%len(letters)]
	}
	return string(b)
}

func main() {
	// Parse the command-line flags
	prefix := flag.String("prefix", "giantcloak", "Prefix to replace 'giantcloak' in fname")
	keySize := flag.Int("size", 2048, "Size of the RSA key in bits")
	flag.Parse()

	// Create the directory if it doesn't exist
	dir := filepath.Join(os.Getenv("HOME"), ".ssh")
	if err := os.MkdirAll(dir, 0700); err != nil {
		fmt.Println("Failed to create directory:", err)
		return
	}

	// Generate a new RSA key pair with the specified key size
	privateKey, err := rsa.GenerateKey(rand.Reader, *keySize)
	if err != nil {
		fmt.Println("Failed to generate key pair:", err)
		return
	}

	// Convert the private key to PEM format
	privateKeyBytes := encodePrivateKeyToPEM(privateKey)

	// Convert the public key to OpenSSH public key format
	publicKeyBytes := encodePublicKeyToOpenSSH(privateKey.PublicKey)

	randomString := GenerateRandomString(5)
	fmt.Println(randomString)

	fname := fmt.Sprintf("id_rsa_%s_%s", *prefix, randomString)

	// Write the private key to a file
	privateKeyPath := filepath.Join(dir, fname)
	privateKeyFile, err := os.OpenFile(privateKeyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		fmt.Println("Failed to write private key to file:", err)
		return
	}
	defer privateKeyFile.Close()
	if _, err := privateKeyFile.Write(privateKeyBytes); err != nil {
		fmt.Println("Failed to write private key to file:", err)
		return
	}

	// Write the public key to a file
	publicKeyPath := filepath.Join(dir, fmt.Sprintf("%s.pub", fname))
	publicKeyFile, err := os.OpenFile(publicKeyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		fmt.Println("Failed to write public key to file:", err)
		return
	}
	defer publicKeyFile.Close()

	if _, err := publicKeyFile.Write(publicKeyBytes); err != nil {
		fmt.Println("Failed to write public key to file:", err)
		return
	}

	fmt.Println("Private key written to:", privateKeyPath)
	fmt.Println("Public key written to:", publicKeyPath)

	keyPaths := KeyPaths{
		PrivateKeyPath: privateKeyPath,
		PublicKeyPath:  publicKeyPath,
		Suffix:         randomString,
		PrivateKey:     filepath.Base(privateKeyPath),
		PublicKey:      filepath.Base(publicKeyPath),
		KeyType:        "rsa",
		Created:        time.Now().UTC().Unix(),
		KeyName:        fmt.Sprintf("id_%s_%s_%s", "rsa", *prefix, randomString),
	}

	jsonData, err := json.MarshalIndent(keyPaths, "", "  ")
	if err != nil {
		fmt.Println("Failed to marshal JSON data:", err)
		return
	}

	jsonFilePath := filepath.Join(".", "giantcloak.json")
	jsonFile, err := os.OpenFile(jsonFilePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		fmt.Println("Failed to write JSON file:", err)
		return
	}
	defer jsonFile.Close()

	if _, err := jsonFile.Write(jsonData); err != nil {
		fmt.Println("Failed to write JSON data:", err)
		return
	}

	fmt.Println("Key paths written to:", jsonFilePath)
}

// Encode the RSA private key to PEM format
func encodePrivateKeyToPEM(privateKey *rsa.PrivateKey) []byte {
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})
	return privateKeyPEM
}

// Encode the RSA public key to OpenSSH public key format
func encodePublicKeyToOpenSSH(publicKey rsa.PublicKey) []byte {
	sshPublicKey, err := ssh.NewPublicKey(&publicKey)
	if err != nil {
		panic(err)
	}
	publicKeyBytes := ssh.MarshalAuthorizedKey(sshPublicKey)
	return publicKeyBytes
}
