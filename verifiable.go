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
	"fmt"

	"github.com/bytemare/ecc"

	"github.com/bytemare/secret-sharing/keys"
)

var errCommitmentNilElement = errors.New("commitment has nil element")

// VssCommitment is the tuple defining a Verifiable Secret Sharing VssCommitment to a secret Polynomial.
type VssCommitment []*ecc.Element

// Commit builds a Verifiable Secret Sharing vector VssCommitment to each of the coefficients
// (of threshold length which uniquely determines the polynomial).
func Commit(g ecc.Group, polynomial Polynomial) VssCommitment {
	coms := make(VssCommitment, len(polynomial))
	for i, coeff := range polynomial {
		coms[i] = g.Base().Multiply(coeff)
	}

	return coms
}

// Verify allows verification of participant id's public key given the VSS commitment to the secret polynomial.
func Verify(g ecc.Group, id uint16, pk *ecc.Element, commitment []*ecc.Element) bool {
	v, err := PubKeyForCommitment(g, id, commitment)
	if err != nil {
		return false
	}

	return pk.Equal(v)
}

// VerifyPublicKeyShare returns whether the PublicKeyShare's public key is valid given its VSS commitment to
// the secret polynomial.
func VerifyPublicKeyShare(p *keys.PublicKeyShare) bool {
	return Verify(p.Group, p.ID, p.PublicKey, p.VssCommitment)
}

// PubKeyForCommitment computes the public key corresponding to the commitment of participant id.
func PubKeyForCommitment(g ecc.Group, id uint16, commitment []*ecc.Element) (*ecc.Element, error) {
	if len(commitment) == 0 || commitment[0] == nil {
		return nil, errCommitmentNilElement
	}

	pk := commitment[0].Copy()
	fmt.Printf("0 > %v\n", pk.Hex())

	switch {
	// If id == 1 we can spare exponentiation and multiplications
	case id == 1:
		for i, com := range commitment[1:] {
			if com == nil {
				return nil, errCommitmentNilElement
			}

			pk.Add(com)
			fmt.Printf(".%d > %v\n", i, pk.Hex())
		}
	case len(commitment) >= 2:
		return comPubKey(g, id, pk, commitment)
	}

	return pk, nil
}

func comPubKey(g ecc.Group, id uint16, pk *ecc.Element, commitment []*ecc.Element) (*ecc.Element, error) {
	if commitment[1] == nil {
		return nil, errCommitmentNilElement
	}

	// if there are elements left and since i == 1, we can spare one exponentiation
	fmt.Println("..0 > " + pk.Hex())
	s := g.NewScalar().SetUInt64(uint64(id))
	pk.Add(commitment[1].Copy().Multiply(s))
	fmt.Println("..1 > " + pk.Hex())

	i := uint64(1)
	is := g.NewScalar()

	for _, com := range commitment[2:] {
		if com == nil {
			return nil, errCommitmentNilElement
		}

		i++
		is.SetUInt64(i)
		pk.Add(com.Copy().Multiply(s.Copy().Pow(is)))
		fmt.Printf("..%d > %v\n", i, pk.Hex())
	}

	return pk, nil
}
