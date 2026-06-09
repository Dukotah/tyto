package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/dukotah/tyto/internal/engagement"
)

// newAuthorizeCmd is the client-side helper for producing authorization material.
// Signing happens on the CLIENT's machine with the CLIENT's private key; tyto
// only ever VERIFIES at run time. This is a convenience so a client without their
// own tooling can still generate a keypair and sign an engagement.
func newAuthorizeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "authorize",
		Short: "Client-side: generate a keypair / sign an engagement",
	}

	keygen := &cobra.Command{
		Use:   "keygen",
		Short: "Generate a client Ed25519 keypair",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			pub, priv, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			fmt.Fprintln(out, "# Give the client_public_key to the tyto operator (pin it in the engagement).")
			fmt.Fprintln(out, "# Keep the private_key SECRET on the client's machine; use it with 'authorize sign'.")
			fmt.Fprintf(out, "client_public_key: %s\n", base64.StdEncoding.EncodeToString(pub))
			fmt.Fprintf(out, "private_key:       %s\n", base64.StdEncoding.EncodeToString(priv))
			return nil
		},
	}

	var engPath, privB64, maxTier, targets string
	sign := &cobra.Command{
		Use:   "sign",
		Short: "Sign an engagement's canonical scope to produce a grant",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if engPath == "" || privB64 == "" {
				return fmt.Errorf("--engagement and --private-key are required")
			}
			eng, err := engagement.Load(engPath)
			if err != nil {
				return err
			}
			priv, err := base64.StdEncoding.DecodeString(privB64)
			if err != nil || len(priv) != ed25519.PrivateKeySize {
				return fmt.Errorf("--private-key is not a valid base64 Ed25519 private key")
			}
			privKey := ed25519.PrivateKey(priv)
			sig := ed25519.Sign(privKey, eng.CanonicalBytes())
			pub := privKey.Public().(ed25519.PublicKey)
			out := cmd.OutOrStdout()
			fmt.Fprintln(out, "# Add this under authorization.grants in the engagement YAML:")
			fmt.Fprintf(out, "  - public_key: %s\n", base64.StdEncoding.EncodeToString(pub))
			fmt.Fprintf(out, "    signature: %s\n", base64.StdEncoding.EncodeToString(sig))
			fmt.Fprintf(out, "    max_tier: %s\n", maxTier)
			if targets == "" {
				fmt.Fprintln(out, "    covers_targets:   # mirror the in-scope targets the client authorizes")
			} else {
				fmt.Fprintln(out, "    covers_targets:")
				for _, t := range splitCSV(targets) {
					fmt.Fprintf(out, "      - {type: domain, value: %s}   # adjust type as needed\n", t)
				}
			}
			return nil
		},
	}
	sign.Flags().StringVar(&engPath, "engagement", "", "engagement YAML to authorize (required)")
	sign.Flags().StringVar(&privB64, "private-key", "", "client base64 Ed25519 private key (required)")
	sign.Flags().StringVar(&maxTier, "max-tier", "high", "highest authorized risk tier: passive|low|medium|high")
	sign.Flags().StringVar(&targets, "targets", "", "comma-separated targets the grant covers (default: all in-scope)")

	cmd.AddCommand(keygen, sign)
	return cmd
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
