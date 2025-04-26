package main

import (
	"github.com/alecthomas/kong"
)

// --- CLI Structure ---

type Globals struct {
	CACertPath string `type:"existingfile" default:"ca-cert.pem" help:"Path to the CA certificate PEM file."`
	CAKeyPath  string `type:"existingfile" default:"ca-key.pem" help:"Path to the CA private key PEM file."`
}

var cli struct {
	Globals

	ProvisionIdentity ProvisionIdentityCmd `cmd:"" help:"Provision a new identity in the Secure Enclave and Keychain."`
	ListIdentities    ListIdentitiesCmd    `cmd:"" help:"List identities stored in the Keychain."`
	ListKeys          ListKeysCmd          `cmd:"" help:"List keys stored in the Secure Enclave."`
	MTLSConnect       MTLSConnectCmd       `cmd:"" help:"Connect to a remote host using mTLS with a keychain identity."`
}

// --- Main Function ---

func main() {
	ctx := kong.Parse(&cli)
	err := ctx.Run(&cli.Globals)
	ctx.FatalIfErrorf(err)
}
