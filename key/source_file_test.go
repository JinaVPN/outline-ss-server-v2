package key

import (
	"io/ioutil"
	"os"
	"reflect"
	"sort"
	"syscall"
	"testing"
	"time"

	"gopkg.in/yaml.v2"
)

const testFile = "outline-test-source-file.yml"

func TestFileSource(t *testing.T) {
	defer func() {
		os.Remove(testFile)
	}()

	config := Config{
		Keys: []Key{
			{ID: "k1", Port: 1234, Cipher: "chacha", Secret: "secret"},
			{ID: "k2", Port: 1234, Cipher: "chacha", Secret: "secret"},
		},
	}
	writeConfig(t, config)

	src := NewFileSource(testFile)

	ch := src.Channel()
	received := []Key{}
	for range config.Keys {
		select {
		case e := <-ch:
			if e.Action != AddAction {
				t.Errorf("Event action, want=%v got=%v", AddAction, e.Action)
			}
			received = append(received, e.Key)
		case <-time.After(500 * time.Millisecond):
			t.Fatalf("Event not received")
		}
	}
	sortKeys(received)
	if !reflect.DeepEqual(config.Keys, received) {
		t.Errorf("Wrong keys received on channel, want=%v got=%v", config.Keys, received)
	}

	// Nothing else should be on channel
	select {
	case <-ch:
		t.Fatalf("Unexpected message received on channel")
	case <-time.After(500 * time.Millisecond):
	}

	// Write new config. Remove one key and add a new one
	config = Config{
		Keys: []Key{
			{ID: "k1", Port: 1234, Cipher: "chacha", Secret: "secret"},
			{ID: "k3", Port: 1234, Cipher: "chacha", Secret: "secret"},
		},
	}
	expectedEvents := []KeyCommand{
		{Action: AddAction, Key: Key{ID: "k3", Port: 1234, Cipher: "chacha", Secret: "secret"}},
		{Action: RemoveAction, Key: Key{ID: "k2", Port: 1234, Cipher: "chacha", Secret: "secret"}},
	}

	writeConfig(t, config)
	syscall.Kill(os.Getpid(), syscall.SIGHUP)

	for _, event := range expectedEvents {
		select {
		case e := <-ch:
			if e.Action != event.Action {
				t.Errorf("Event action, want=%v got=%v", event.Action, e.Action)
			}
			if e.Key != event.Key {
				t.Errorf("Wrong key received on event, want=%v got=%v", event.Key, e.Key)
			}
		case <-time.After(500 * time.Millisecond):
			t.Fatalf("Event not received")
		}
	}

	src.Close()
}

func writeConfig(t *testing.T, config Config) {
	sortKeys(config.Keys)
	c, _ := yaml.Marshal(config)
	err := ioutil.WriteFile(testFile, c, 0666)
	if err != nil {
		t.Fatalf("Failed to write temp config file")
	}
}

func sortKeys(k []Key) {
	sort.Slice(k, func(i, j int) bool {
		return k[i].ID < k[j].ID
	})
}
