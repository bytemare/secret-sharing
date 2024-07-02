// SPDX-License-ID: MIT
//
// Copyright (C) 2023 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package secretsharing

import (
	group "github.com/bytemare/crypto"
)

// Commitment is the tuple defining a Verifiable Secret Sharing Commitment.
type Commitment []*group.Element

// Commit builds a VSS vector commitment to each of the coefficients
// (of threshold length which uniquely determines the polynomial).
func Commit(g group.Group, polynomial Polynomial) Commitment {
	coms := make(Commitment, len(polynomial))
	for i, coeff := range polynomial {
		coms[i] = g.Base().Multiply(coeff)
	}

	return coms
}

// Verify allows verification of a participant's secret share given its public key and the VSS commitment
// to the secret polynomial.
func Verify(g group.Group, id uint64, pk *group.Element, coms Commitment) bool {
	if len(coms) == 0 {
		return false
	}

	ids := g.NewScalar().SetUInt64(id)
	prime := coms[0].Copy()
	one := g.NewScalar().One()
	j := g.NewScalar().One()
	i := 1

	switch {
	// If id == 1 we can spare exponentiation and multiplications
	case id == 1:
		for _, com := range coms[1:] {
			prime.Add(com)
		}
	case len(coms) >= 2:
		// if there are elements left and since j == 1, we can spare one exponentiation
		prime.Add(coms[1].Copy().Multiply(ids))
		j.Add(one)

		i++

		fallthrough
	default:
		for _, com := range coms[i:] {
			prime.Add(com.Copy().Multiply(ids.Copy().Pow(j)))
			j.Add(one)
		}
	}

	return pk.Equal(prime) == 1
}
