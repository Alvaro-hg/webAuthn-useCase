package main

import "github.com/go-webauthn/webauthn/protocol"

type FinishRegistrationRequest struct {
	Name     string                              `json:"name" mapstructure:"name"`
	Response protocol.CredentialCreationResponse `json:"response" mapstructure:"response"`
}

type FinishAuthenticationRequest struct {
	Name     string                               `json:"name" mapstructure:"name"`
	Response protocol.CredentialAssertionResponse `json:"response" mapstructure:"response"`
}
