package keysource

import (
	"fmt"
	"log/slog"

	"github.com/Jigsaw-Code/outline-sdk/transport/shadowsocks"
	"github.com/Jigsaw-Code/outline-ss-server/service"
)

type KeyUpdater struct {
	Ciphers     service.CipherList
	ciphersByID map[string]func()
}

func (c *KeyUpdater) AddKey(key Key) error {
	cryptoKey, err := shadowsocks.NewEncryptionKey(key.Cipher, key.Secret)
	if err != nil {
		return fmt.Errorf("failed to create encyption key for key %v: %w", key.ID, err)
	}
	entry := service.MakeCipherEntry(key.ID, cryptoKey, key.Secret)
	slog.Info("Added key ", "keyID", key.ID)
	rmFunc := c.Ciphers.AddEntry(&entry)
	// Store the remove callback in a map for fast removal
	c.ciphersByID[key.ID] = rmFunc
	return nil
}

func (c *KeyUpdater) RemoveKey(key Key) error {
	if c.Ciphers == nil {
		return fmt.Errorf("no Cipher available while removing key %v", key.ID)
	}
	rmFunc, exists := c.ciphersByID[key.ID]
	if exists {
		rmFunc()
		return nil
	} else {
		return fmt.Errorf("key %v was not found", key.ID)
	}
}
