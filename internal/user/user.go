package user

import (
	"encoding/json"
	"fmt"

	"github.com/go-webauthn/webauthn/webauthn"
)

type User struct {
	ID          []byte
	DisplayName string
	Name        string

	creds []webauthn.Credential
}

// WebAuthnCredentials implements webauthn.User.
func (o User) WebAuthnCredentials() []webauthn.Credential {
	return o.creds
}

// WebAuthnDisplayName implements webauthn.User.
func (o User) WebAuthnDisplayName() string {
	return o.DisplayName
}

// WebAuthnID implements webauthn.User.
func (o User) WebAuthnID() []byte {
	return o.ID
}

// WebAuthnIcon implements webauthn.User.
func (o User) WebAuthnIcon() string {
	return ""
}

// WebAuthnName implements webauthn.User.
func (o User) WebAuthnName() string {
	return o.Name
}

func (u *User) UnmarshalCreds(data []byte) error {
	var creds []webauthn.Credential
	if err := json.Unmarshal(data, &creds); err != nil {
		return err
	}
	u.creds = creds
	return nil
}

func (o *User) AddCredential(credential *webauthn.Credential) {
	fmt.Println("creds length before adding", len(o.creds))
	if len(credential.PublicKey) == 0 {
		fmt.Println("No publicKey in the credential we are adding")
	}
	o.creds = append(o.creds, *credential)
}

func (o *User) UpdateCredential(credential *webauthn.Credential) {
	for i, c := range o.creds {
		if string(c.ID) == string(credential.ID) {
			o.creds[i] = *credential
		}
	}
}
