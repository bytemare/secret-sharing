// SPDX-License-Identifier: MIT
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
func Verify(g group.Group, id *group.Scalar, pk *group.Element, coms Commitment) bool {
	prime := g.NewElement().Identity()
	one := g.NewScalar().One()

	j := g.NewScalar().Zero()
	for _, com := range coms {
		prime.Add(com.Copy().Multiply(id.Copy().Pow(j)))
		j.Add(one)
	}

	return pk.Equal(prime) == 1
}
