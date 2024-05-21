// SPDX-License-Identifier: MIT
//
// Copyright (C) 2023 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package secretsharing_test

import (
	"fmt"

	group "github.com/bytemare/crypto"

	secretsharing "github.com/bytemare/secret-sharing"
)

// ExampleShardAndCombine shows how to split a private key into shares and how to recombine it from a
// subset of shares.
func ExampleShardAndCombine() {
	// These are the configuration parameters
	g := group.Ristretto255Sha512
	threshold := uint(3)    // threshold is the minimum amount of necessary shares to recombine the secret
	shareholders := uint(7) // the total amount of key share-holders

	// This is the global secret to be shared
	secret := g.NewScalar().Random()

	// Shard the secret into shares
	shares, err := secretsharing.Shard(g, secret, threshold, shareholders)
	if err != nil {
		panic(err)
	}

	// Assemble a subset of shares to recover the secret. We must use [threshold+1] or more shares.
	subset := []*secretsharing.KeyShare{
		shares[5], shares[0], shares[3],
	}

	// Combine the subset of shares.
	recovered, err := secretsharing.Combine(g, subset)
	if err != nil {
		panic(err)
	}

	if recovered.Equal(secret) != 1 {
		fmt.Println("ERROR: recovery failed")
	} else {
		fmt.Println("Key split into shares and recombined with a subset of shares!")
	}

	// Output: Key split into shares and recombined with a subset of shares!
}

// ExampleShardAndVerify shows how to split a private key into shares and how one can verify a secret, should the dealer
// be potentially malicious.
func ExampleShardAndVerify() {
	// These are the configuration parameters
	g := group.Ristretto255Sha512
	threshold := uint(3)    // threshold is minimum amount of necessary shares to recombine the secret
	shareholders := uint(7) // the total amount of key share-holders

	// This is the global secret to be shared
	secret := g.NewScalar().Random()

	// Shard the secret into shares
	shares, polynomial, err := secretsharing.ShardReturnPolynomial(g, secret, threshold, shareholders)
	if err != nil {
		panic(err)
	}

	// Commit to be computed by the dealer.
	commitment := secretsharing.Commit(g, polynomial)

	// You can verify any public key using the commitment. This can be run by a single party or any other with access to
	// the party's public key.
	for _, keyshare := range shares {
		// Let's derive the public key. Other parties won't have access to the private key, naturally.
		publicKey := g.Base().Multiply(keyshare.SecretKey)

		// Verify that the keys hare's public key is consistent with the commitment.
		if !secretsharing.Verify(g, keyshare.Identifier, publicKey, commitment) {
			panic("invalid public key for shareholder")
		}
	}

	fmt.Println("All key shares verified.")

	// Output: All key shares verified.
}
