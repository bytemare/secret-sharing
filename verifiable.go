// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package secretsharing

import (
	"errors"

	group "github.com/bytemare/crypto"
)

var errCommitmentNilElement = errors.New("commitment has nil element")

// Commitment is the tuple defining a Verifiable Secret Sharing Commitment to a secret Polynomial.
type Commitment []*group.Element

// Commit builds a Verifiable Secret Sharing vector Commitment to each of the coefficients
// (of threshold length which uniquely determines the polynomial).
func Commit(g group.Group, polynomial Polynomial) Commitment {
	coms := make(Commitment, len(polynomial))
	for i, coeff := range polynomial {
		coms[i] = g.Base().Multiply(coeff)
	}

	return coms
}

// Verify allows verification of participant id's public key given the VSS commitment to the secret polynomial.
func Verify(g group.Group, id uint16, pk *group.Element, commitment []*group.Element) bool {
	v, err := PubKeyForCommitment(g, id, commitment)
	if err != nil {
		return false
	}

	return pk.Equal(v) == 1
}

// PubKeyForCommitment computes the public key corresponding to the commitment of participant id.
func PubKeyForCommitment(g group.Group, id uint16, commitment []*group.Element) (*group.Element, error) {
	if len(commitment) == 0 || commitment[0] == nil {
		return nil, errCommitmentNilElement
	}

	pk := commitment[0].Copy()

	switch {
	// If id == 1 we can spare exponentiation and multiplications
	case id == 1:
		for _, com := range commitment[1:] {
			if com == nil {
				return nil, errCommitmentNilElement
			}

			pk.Add(com)
		}
	case len(commitment) >= 2:
		return comPubKey(g, id, pk, commitment)
	}

	return pk, nil
}

func comPubKey(g group.Group, id uint16, pk *group.Element, commitment []*group.Element) (*group.Element, error) {
	if commitment[1] == nil {
		return nil, errCommitmentNilElement
	}

	// if there are elements left and since i == 1, we can spare one exponentiation
	s := g.NewScalar().SetUInt64(uint64(id))
	pk.Add(commitment[1].Copy().Multiply(s))

	i := uint64(1)
	is := g.NewScalar()

	for _, com := range commitment[2:] {
		if com == nil {
			return nil, errCommitmentNilElement
		}

		i++
		is.SetUInt64(i)
		pk.Add(com.Copy().Multiply(s.Copy().Pow(is)))
	}

	return pk, nil
}
