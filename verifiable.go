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

	"github.com/bytemare/ecc"

	"github.com/bytemare/secret-sharing/keys"
)

var (
	errCommitmentNilElement = errors.New("commitment has nil element")
	errCommitmentWrongGroup = errors.New("commitment element has incompatible EC group")
	errPolynomialEmpty      = errors.New("polynomial is empty")
	errIdentifierIsZero     = errors.New("identifier is zero")
)

// VssCommitment is the tuple defining a Verifiable Secret Sharing VssCommitment to a secret Polynomial.
type VssCommitment []*ecc.Element

// Commit builds a Verifiable Secret Sharing vector VssCommitment to each of the coefficients
// (of threshold length which uniquely determines the polynomial).
func Commit(g ecc.Group, polynomial Polynomial) (commitment VssCommitment, err error) {
	defer func() {
		if recover() != nil {
			commitment = nil
			err = errMalformedCrypto
		}
	}()

	if !g.Available() {
		return nil, errInvalidGroup
	}

	if len(polynomial) == 0 {
		return nil, errPolynomialEmpty
	}

	for _, coefficient := range polynomial {
		if coefficient == nil {
			return nil, errPolyHasNilCoeff
		}

		if !scalarInGroup(coefficient, g) {
			return nil, errScalarGroup
		}
	}

	coms := make(VssCommitment, len(polynomial))
	for i, coeff := range polynomial {
		coms[i] = g.Base().Multiply(coeff)
	}

	return coms, nil
}

// Verify allows verification of participant id's public key given the VSS commitment to the secret polynomial.
func Verify(g ecc.Group, id uint16, pk *ecc.Element, commitment []*ecc.Element) (verified bool) {
	defer func() {
		if recover() != nil {
			verified = false
		}
	}()

	if !elementInGroup(pk, g) {
		return false
	}

	v, err := PubKeyForCommitment(g, id, commitment)
	if err != nil {
		return false
	}

	return pk.Equal(v)
}

// VerifyPublicKeyShare returns whether the PublicKeyShare's public key is valid given its VSS commitment to
// the secret polynomial.
func VerifyPublicKeyShare(p *keys.PublicKeyShare) (verified bool) {
	defer func() {
		if recover() != nil {
			verified = false
		}
	}()

	if p == nil {
		return false
	}

	return Verify(p.Group(), p.Identifier(), p.PublicKey(), p.Commitment())
}

// PubKeyForCommitment computes the public key corresponding to the commitment of participant id.
func PubKeyForCommitment(g ecc.Group, id uint16, commitment []*ecc.Element) (pk *ecc.Element, err error) {
	defer func() {
		if recover() != nil {
			pk = nil
			err = errMalformedCrypto
		}
	}()

	if !g.Available() {
		return nil, errInvalidGroup
	}

	if id == 0 {
		return nil, errIdentifierIsZero
	}

	if err = validateCommitment(g, commitment); err != nil {
		return nil, err
	}

	pk = commitment[0].Copy()

	switch {
	// If id == 1 we can spare exponentiation and multiplications
	case id == 1:
		for _, com := range commitment[1:] {
			pk.Add(com)
		}
	case len(commitment) >= 2:
		return comPubKey(g, id, pk, commitment), nil
	}

	return pk, nil
}

func comPubKey(g ecc.Group, id uint16, pk *ecc.Element, commitment []*ecc.Element) *ecc.Element {
	// if there are elements left and since i == 1, we can spare one exponentiation
	s := g.NewScalar().SetUInt64(uint64(id))
	pk.Add(commitment[1].Copy().Multiply(s))

	i := uint64(1)
	is := g.NewScalar()

	for _, com := range commitment[2:] {
		i++
		is.SetUInt64(i)
		pk.Add(com.Copy().Multiply(s.Copy().Pow(is)))
	}

	return pk
}

func validateCommitment(g ecc.Group, commitment []*ecc.Element) error {
	if len(commitment) == 0 {
		return errCommitmentNilElement
	}

	for _, element := range commitment {
		if element == nil {
			return errCommitmentNilElement
		}

		if !elementInGroup(element, g) {
			return errCommitmentWrongGroup
		}
	}

	return nil
}

func elementInGroup(element *ecc.Element, g ecc.Group) (ok bool) {
	if element == nil || !g.Available() {
		return false
	}

	defer func() {
		if recover() != nil {
			ok = false
		}
	}()

	return element.Group() == g
}
