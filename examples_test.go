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

// ExampleSecretSharing_Shard show how to split a private key into shares and how to recombine it from a
// subset of shares.
func Example_secretSharing_Shard() {
	// These are the configuration parameters
	g := group.Ristretto255Sha512
	threshold := uint(3)    // the minimum amount of necessary shares to recombine the secret
	shareholders := uint(7) // the total amount of key share-holders

	// This is the global secret to be shared
	secret := g.NewScalar().Random()

	// Shard the secret into shares
	shares, err := secretsharing.Shard(g, secret, threshold, shareholders)
	if err != nil {
		panic(err)
	}

	// Assemble a subset of shares to recover the secret. We must use [threshold] or more shares.
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
