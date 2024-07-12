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

// ExampleShard shows how to split a private key into shares and how to recombine it from a
// subset of shares. For an example of Verifiable Secret Sharing, see ExampleVerify.
func ExampleShard() {
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

	// Assemble a subset of shares to recover the secret. We must use threshold or more shares.
	subset := []secretsharing.Share{
		shares[5], shares[0], shares[3],
	}

	// Combine the subset of shares.
	recovered, err := secretsharing.CombineShares(g, subset)
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

// ExampleShardAndVerify shows how to split a private key into shares, commit to the underlying polynomial, and verify
// the generated public keys given the initial commitment.
func ExampleVerify() {
	// These are the configuration parameters
	g := group.Ristretto255Sha512
	threshold := uint(3)    // threshold is minimum amount of necessary shares to recombine the secret
	shareholders := uint(7) // the total amount of key share-holders

	// This is the global secret to be shared
	secret := g.NewScalar().Random()

	// Shard the secret into shares
	shares, err := secretsharing.ShardAndCommit(g, secret, threshold, shareholders)
	if err != nil {
		panic(err)
	}

	// You can verify any public key using the commitment. This can be run by a single participant or any other
	// participant access to the participant's public key.
	for _, keyshare := range shares {
		// Let's get the public key. Other parties won't have access to the private key, naturally.
		publicShare := keyshare.Public()

		// Verify that the key share's public key is consistent with the commitment.
		if !secretsharing.Verify(g, publicShare.ID, publicShare.PublicKey, publicShare.Commitment) {
			panic("invalid public key for shareholder")
		}
	}

	fmt.Println("All key shares verified.")

	// Output: All key shares verified.
}
