package main

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/Jigsaw-Code/outline-sdk/transport/shadowsocks"
	"github.com/Jigsaw-Code/outline-ss-server/key"
	"github.com/Jigsaw-Code/outline-ss-server/service"
)

type Source struct {
	Url string // URL of the key source, e.g. "file://path/to/keys"
}

type KeyUpdater struct {
	Ciphers     service.CipherList
	ciphersByID map[string]*service.CipherEntry
}

func (c *KeyUpdater) AddKey(key key.Key) error {
	cryptoKey, err := shadowsocks.NewEncryptionKey(key.Cipher, key.Secret)
	if err != nil {
		return fmt.Errorf("failed to create encyption key for key %v: %w", key.ID, err)
	}
	entry := service.MakeCipherEntry(key.ID, cryptoKey, key.Secret)
	slog.Info("Added key ", "keyID", key.ID)
	c.Ciphers.AddEntry(&entry)
	// Store the entry in a map for fast removal
	c.ciphersByID[key.ID] = &entry
	return nil
}

func (c *KeyUpdater) RemoveKey(key key.Key) error {
	if c.Ciphers == nil {
		return fmt.Errorf("no Cipher available while removing key %v", key.ID)
	}
	entry, exists := c.ciphersByID[key.ID]
	if exists {
		c.Ciphers.RemoveEntry(entry)
		return nil
	} else {
		return fmt.Errorf("key %v was not found", key.ID)
	}
}

func (s *Source) Register(c service.CipherList, logger *slog.Logger) {
	if strings.HasPrefix(s.Url, "file://") {
		newFileUpdater(c, key.NewFileSource(s.Url[7:]), logger).Listen()
	}
}

type FileUpdater struct {
	KeyUpdater
	fileSource key.Source
	logger     *slog.Logger
}

func newFileUpdater(c service.CipherList, s key.Source, logger *slog.Logger) *FileUpdater {
	fu := &FileUpdater{
		logger:     logger,
		fileSource: s,
	}
	fu.KeyUpdater.Ciphers = c
	fu.KeyUpdater.ciphersByID = make(map[string]*service.CipherEntry)
	return fu
}

func (fu *FileUpdater) Listen() {
	go func() {
		for cmd := range fu.fileSource.Channel() {
			switch cmd.Action {
			case key.AddAction:
				fu.KeyUpdater.AddKey(cmd.Key)
				fu.logger.Info("Added key ", "keyID", cmd.Key.ID)
			case key.RemoveAction:
				fu.KeyUpdater.RemoveKey(cmd.Key)
				fu.logger.Info("Removed key ", "keyID", cmd.Key.ID)
			}
		}
	}()
}
