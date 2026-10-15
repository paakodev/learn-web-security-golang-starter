package passwords

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

const (
	MaxLength   = 128
	MemoryUse   = 19 * 1024 // 19 MiB of memory for Argon2id
	Iterations  = 2
	Parallelism = 1
	KeyLen      = 32
)

func Hash(password string) (string, error) {
	if utf8.RuneCountInString(password) > MaxLength {
		return "", fmt.Errorf("password exceeds maximum length of %d", MaxLength)
	}
	var salt [16]byte
	_, err := rand.Read(salt[:])
	if err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}
	passwordHash := argon2.IDKey([]byte(password), salt[:], Iterations, MemoryUse, Parallelism, KeyLen)

	return encodeArgon2idHash(argon2idHash{
		version:     argon2.Version,
		memoryKiB:   MemoryUse,
		iterations:  Iterations,
		parallelism: Parallelism,
		salt:        salt[:],
		derivedKey:  passwordHash,
	}), nil
}

func Verify(password, encodedHash string) bool {
	if utf8.RuneCountInString(password) > MaxLength {
		return false
	}
	if expectedHash, ok := decodeLegacyHash(encodedHash); ok {
		candidateHash := sha256.Sum256([]byte(password))
		return subtle.ConstantTimeCompare(candidateHash[:], expectedHash) == 1
	}
	argon2idHash, ok := parseArgon2idHash(encodedHash)
	if !ok {
		return false
	}
	if argon2idHash.version != argon2.Version {
		return false
	}
	candidateHash := argon2.IDKey(
		[]byte(password),
		argon2idHash.salt,
		argon2idHash.iterations,
		argon2idHash.memoryKiB,
		argon2idHash.parallelism,
		uint32(len(argon2idHash.derivedKey)),
	)
	return subtle.ConstantTimeCompare(candidateHash, argon2idHash.derivedKey) == 1
}

func NeedsRehash(encodedHash string) bool {
	if _, ok := decodeLegacyHash(encodedHash); ok {
		return true
	}
	if argon2idHash, ok := parseArgon2idHash(encodedHash); ok {
		if argon2idHash.version != argon2.Version || argon2idHash.memoryKiB != MemoryUse || argon2idHash.iterations != Iterations || argon2idHash.parallelism != Parallelism || uint32(len(argon2idHash.derivedKey)) != KeyLen {
			return true
		}
	}
	return false
}
