// SPDX-License-Identifier: MIT
//
// Copyright (C) 2023 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package secretsharing_test

import (
	group "github.com/bytemare/crypto"

	secretsharing "github.com/bytemare/secret-sharing"
)

// ExampleSecretSharing_Shard show how to split a private key into shares and how to recombine it from a
// subset of shares.
func ExampleSecretSharing_Shard() {
	// These are the configuration parameters
	g := group.Ristretto255Sha512
	threshold := uint(2)
	shareholders := uint(3)

	// This is the global secret to be shared
	secret := g.NewScalar().Random()

	// Here we create a secret sharing instance
	ss, err := secretsharing.New(g, threshold)
	if err != nil {
		panic(err)
	}

	// and now we split the secret into shares
	shares, _, err := ss.Shard(secret, shareholders)
	if err != nil {
		panic(err)
	}

	// here we recombine the shares to recover the secret
	subset := []*secretsharing.KeyShare{
		shares[0], shares[1],
	}

	for k := 0; k <= int(shareholders); k++ {
		recovered, err := secretsharing.Combine(g, threshold, subset)
		if err != nil {
			panic(err)
		}

		if recovered.Equal(secret) != 1 {
			panic("invalid recovered secret")
		}
	}
}
