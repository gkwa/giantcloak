package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"
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
	flag.Parse()

	// Create the directory if it doesn't exist
	dir := filepath.Join(os.Getenv("HOME"), ".ssh")
	if err := os.MkdirAll(dir, 0700); err != nil {
		fmt.Println("Failed to create directory:", err)
		return
	}

	// Generate a new Ed25519 key pair
	privateKey, publicKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Println("Failed to generate key pair:", err)
		return
	}

	// Convert the private key to hex format
	privateKeyHex := hex.EncodeToString(privateKey)

	// Convert the public key to hex format
	publicKeyHex := hex.EncodeToString(publicKey)

	randomString := GenerateRandomString(5)
	fmt.Println(randomString)

	fname := fmt.Sprintf("id_ed25519_%s_%s", *prefix, randomString)

	// Write the private key to a file
	privateKeyPath := filepath.Join(dir, fname)
	privateKeyFile, err := os.OpenFile(privateKeyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		fmt.Println("Failed to write private key to file:", err)
		return
	}
	defer privateKeyFile.Close()
	if _, err := privateKeyFile.WriteString(privateKeyHex); err != nil {
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
	if _, err := publicKeyFile.WriteString(publicKeyHex); err != nil {
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
		KeyType:        "ed25519",
		Created:        time.Now().UTC().Unix(),
		KeyName:        fmt.Sprintf("id_%s_%s_%s", "ed25519", *prefix, randomString),
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
