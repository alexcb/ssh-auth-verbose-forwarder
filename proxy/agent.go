package proxy

import (
	"fmt"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type Agent struct {
	a agent.ExtendedAgent
}

func NewAgent(a agent.ExtendedAgent) agent.ExtendedAgent {
	return &Agent{
		a: a,
	}
}

// List returns the identities known to the agent.
func (ap *Agent) List() ([]*agent.Key, error) {
	fmt.Printf("List()\n")
	return ap.a.List()
}

// Sign has the agent sign the data using a protocol 2 key as defined
// in [PROTOCOL.agent] section 2.6.2.
func (ap *Agent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	fmt.Printf("Sign %v %v\n", key, data)
	return ap.a.Sign(key, data)
}

// Add adds a private key to the agent.
func (ap *Agent) Add(key agent.AddedKey) error {
	fmt.Printf("Add %v\n", key)
	return ap.a.Add(key)
}

// Remove removes all identities with the given public key.
func (ap *Agent) Remove(key ssh.PublicKey) error {
	fmt.Printf("Remove %v\n", key)
	return ap.a.Remove(key)
}

// RemoveAll removes all identities.
func (ap *Agent) RemoveAll() error {
	fmt.Printf("RemoveAll\n")
	return ap.a.RemoveAll()
}

// Lock locks the agent. Sign and Remove will fail, and List will empty an empty list.
func (ap *Agent) Lock(passphrase []byte) error {
	fmt.Printf("Lock %v\n", passphrase)
	return ap.a.Lock(passphrase)
}

// Unlock undoes the effect of Lock
func (ap *Agent) Unlock(passphrase []byte) error {
	fmt.Printf("Unlock %v\n", passphrase)
	return ap.a.Unlock(passphrase)
}

// Signers returns signers for all the known keys.
func (ap *Agent) Signers() ([]ssh.Signer, error) {
	fmt.Printf("Signers\n")
	return ap.a.Signers()
}

// SignWithFlags signs like Sign, but allows for additional flags to be sent/received
func (ap *Agent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	fmt.Printf("SignWithFlags %v %v %v\n", key, data, flags)
	return ap.a.SignWithFlags(key, data, flags)
}

// Extension processes a custom extension request. Standard-compliant agents are not
// required to support any extensions, but this method allows agents to implement
// vendor-specific methods or add experimental features. See [PROTOCOL.agent] section 4.7.
// If agent extensions are unsupported entirely this method MUST return an
// ErrExtensionUnsupported error. Similarly, if just the specific extensionType in
// the request is unsupported by the agent then ErrExtensionUnsupported MUST be
// returned.
//
// In the case of success, since [PROTOCOL.agent] section 4.7 specifies that the contents
// of the response are unspecified (including the type of the message), the complete
// response will be returned as a []byte slice, including the "type" byte of the message.
func (ap *Agent) Extension(extensionType string, contents []byte) ([]byte, error) {
	fmt.Printf("Extension %v %v\n", extensionType, contents)
	return ap.a.Extension(extensionType, contents)
}
