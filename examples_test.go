// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package secretsharing_test

import (
	"encoding/json"
	"fmt"

	"github.com/bytemare/ecc"

	"github.com/bytemare/secret-sharing/keys"

	secretsharing "github.com/bytemare/secret-sharing"
)

// ExampleShard shows the recommended reconstruction path: split a private key with
// commitments, build a validated public registry, and recombine a submitted subset
// with registry-backed verification.
func ExampleShard() {
	// These are the configuration parameters
	g := ecc.Ristretto255Sha512
	threshold := uint16(3)    // threshold is the minimum amount of necessary shares to recombine the secret
	shareholders := uint16(7) // the max amount of key share-holders

	// This is the global secret to be shared
	secret := g.NewScalar().Random()

	// Shard the secret into shares and commit to the sharing polynomial.
	shares, err := secretsharing.ShardAndCommit(g, secret, threshold, shareholders)
	if err != nil {
		panic(err)
	}

	// Build the public registry from the public part of every generated share.
	// NewPublicKeyShareRegistry validates that the registry is complete and internally consistent.
	publicShares := make([]*keys.PublicKeyShare, 0, len(shares))
	for _, share := range shares {
		publicShares = append(publicShares, share.PublicKeyShare())
	}

	registry, err := keys.NewPublicKeyShareRegistry(
		g,
		threshold,
		shareholders,
		shares[0].VerificationKey(),
		publicShares,
	)
	if err != nil {
		panic(err)
	}

	// Assemble a subset of shares to recover the secret. We must use threshold or more shares.
	subset := []*keys.KeyShare{
		shares[5], shares[0], shares[3],
	}

	// CombineVerifiedShares checks the registry and submitted shares before reconstruction.
	recovered, err := secretsharing.CombineVerifiedShares(registry, subset)
	if err != nil {
		panic(err)
	}

	if !recovered.Equal(secret) {
		fmt.Println("ERROR: recovery failed")
	} else {
		fmt.Println("Key split into shares and recombined with a subset of shares!")
	}

	// Output: Key split into shares and recombined with a subset of shares!
}

// ExampleCombineShares_trustedLocalShares shows raw reconstruction for shares that are already trusted by local context.
// CombineShares does not authenticate share membership or detect well-formed tampering.
func ExampleCombineShares_trustedLocalShares() {
	g := ecc.Ristretto255Sha512
	threshold := uint16(2)

	secret := g.NewScalar().Random()
	shares, err := secretsharing.Shard(g, secret, threshold, 3)
	if err != nil {
		panic(err)
	}

	recovered, err := secretsharing.CombineShares([]*keys.KeyShare{shares[0], shares[2]}, threshold)
	if err != nil {
		panic(err)
	}

	fmt.Println(recovered.Equal(secret))

	// Output: true
}

// ExampleVerify shows a per-share Feldman public-key consistency check. Use
// CombineVerifiedShares with a validated registry for high-assurance reconstruction.
func ExampleVerify() {
	// These are the configuration parameters
	g := ecc.Ristretto255Sha512
	threshold := uint16(3)    // threshold is minimum amount of necessary shares to recombine the secret
	shareholders := uint16(7) // the max amount of key share-holders

	// This is the global secret to be shared
	secret := g.NewScalar().Random()

	// Shard the secret into shares
	shares, err := secretsharing.ShardAndCommit(g, secret, threshold, shareholders)
	if err != nil {
		panic(err)
	}

	// You can verify any public key using the commitment. This per-share check is useful for public material, but it
	// does not replace verified reconstruction against a complete registry.
	for _, keyshare := range shares {
		// Let's get the public key. Other parties won't have access to the private key, naturally.
		publicShare := keyshare.PublicKeyShare()

		// Verify that the key share's public key is consistent with the commitment.
		if !secretsharing.Verify(g, publicShare.Identifier(), publicShare.PublicKey(), publicShare.Commitment()) {
			panic("invalid public key for shareholder")
		}
	}

	fmt.Println("All public key shares passed the per-share check.")

	// Output: All public key shares passed the per-share check.
}

func Example_jsonDecoding() {
	g := ecc.Ristretto255Sha512
	shares, err := secretsharing.ShardAndCommit(g, g.NewScalar().Random(), 2, 3)
	if err != nil {
		panic(err)
	}

	publicShares := make([]*keys.PublicKeyShare, len(shares))
	for _, share := range shares {
		publicShares[share.Identifier()-1] = share.PublicKeyShare()
	}

	// PublicKeyShareRegistry JSON contains only public registry material. KeyShare
	// JSON contains secret-share material and should only be used on protected
	// storage or transport paths intended to carry private shares.
	registry, err := keys.NewPublicKeyShareRegistry(g, 2, 3, shares[0].VerificationKey(), publicShares)
	if err != nil {
		panic(err)
	}

	registryJSON, err := json.Marshal(registry)
	if err != nil {
		panic(err)
	}

	var decodedRegistry keys.PublicKeyShareRegistry
	if err = json.Unmarshal(registryJSON, &decodedRegistry); err != nil {
		panic(err)
	}

	fmt.Println(decodedRegistry.Get(shares[0].Identifier()) != nil)

	// Output: true
}
