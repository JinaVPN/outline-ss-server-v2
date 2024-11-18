package key

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	onet "github.com/Jigsaw-Code/outline-ss-server/net"
	"github.com/shadowsocks/go-shadowsocks2/socks"
	"gopkg.in/yaml.v2"
)

type fileSource struct {
	filename     string
	existingKeys map[string]Key
	closeCh      chan bool
}

type Config struct {
	Keys []Key
}

func NewFileSource(filename string) Source {
	return &fileSource{
		filename:     filename,
		existingKeys: make(map[string]Key),
		closeCh:      make(chan bool),
	}
}

func (f *fileSource) Channel() chan KeyCommand {
	ch := make(chan KeyCommand)

	go func() {
		f.loadKeys(ch)

		sigHup := make(chan os.Signal, 1)
		signal.Notify(sigHup, syscall.SIGHUP)

		for {
			select {
			case <-f.closeCh:
				signal.Stop(sigHup)
				close(sigHup)
				close(ch)
				return
			case <-sigHup:
				slog.Info("Updating config")
				f.loadKeys(ch)
			}
		}
	}()

	return ch
}

func (f *fileSource) loadKeys(ch chan KeyCommand) {
	config, err := readConfig(f.filename)
	if err != nil {
		slog.Error(fmt.Sprintf("Failed to read config file %v: %v", f.filename, err))
		log.Println("failed to read config file")
		return
	}

	newKeys := make(map[string]Key, len(config.Keys))
	for _, k := range config.Keys {
		if _, ok := f.existingKeys[k.ID]; !ok {
			ch <- KeyCommand{
				Action: AddAction,
				Key:    k,
			}
		}
		newKeys[k.ID] = k
	}

	for _, k := range f.existingKeys {
		if _, ok := newKeys[k.ID]; !ok {
			ch <- KeyCommand{
				Action: RemoveAction,
				Key:    k,
			}
		}
	}

	f.existingKeys = newKeys
}

func readConfig(filename string) (*Config, error) {
	config := Config{}
	configData, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	err = yaml.Unmarshal(configData, &config)
	return &config, err
}

func (f *fileSource) Close() error {
	close(f.closeCh)
	return nil
}

func (f *fileSource) SendEvent(e KeyEvent) {}

func (f *fileSource) WrapConn(keyID string, writer onet.DuplexConn, reader io.Reader, eventTemplate KeyEvent) (onet.DuplexConn, io.Reader, func(socks.Addr, onet.DuplexConn)) {
	return writer, reader, nil
}
