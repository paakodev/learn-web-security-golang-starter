package orders

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/bootdotdev/learn-web-security/internal/storage"
)

type ShippingDetails struct {
	Name       string `json:"name"`
	Address    string `json:"address"`
	City       string `json:"city"`
	Region     string `json:"region"`
	PostalCode string `json:"postalCode"`
}

type serializedShippingDetails struct {
	Name       *string `json:"name"`
	Address    *string `json:"address"`
	City       *string `json:"city"`
	Region     *string `json:"region"`
	PostalCode *string `json:"postalCode"`
}

func EncryptShippingDetails(details ShippingDetails, encryptionKeyring *storage.Keyring) (string, error) {
	if encryptionKeyring == nil {
		return "", errors.New("encryption keyring is required")
	}
	plaintext, err := json.Marshal(details)
	if err != nil {
		return "", fmt.Errorf("serialize shipping details: %w", err)
	}
	return encryptionKeyring.Encrypt(plaintext)
}

func DecryptShippingDetails(serialized string, encryptionKeyring *storage.Keyring) (ShippingDetails, error) {
	if encryptionKeyring == nil {
		return ShippingDetails{}, errors.New("encryption keyring is required")
	}
	decryptedContents, err := encryptionKeyring.Decrypt(serialized)
	if err != nil {
		return ShippingDetails{}, fmt.Errorf("decrypt shipping details: %w", err)
	}
	var details serializedShippingDetails
	if err := json.Unmarshal(decryptedContents, &details); err != nil || details.Name == nil || details.Address == nil || details.City == nil || details.Region == nil || details.PostalCode == nil {
		return ShippingDetails{}, errors.New("invalid shipping details")
	}
	return ShippingDetails{
		Name:       *details.Name,
		Address:    *details.Address,
		City:       *details.City,
		Region:     *details.Region,
		PostalCode: *details.PostalCode,
	}, nil
}
