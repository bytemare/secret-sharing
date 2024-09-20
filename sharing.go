// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package secretsharing provides Shamir Secret Sharing operations.
package secretsharing

import (
	"errors"

	group "github.com/bytemare/crypto"
)

var (
	errThresholdIsZero  = errors.New("threshold is zero")
	errNoShares         = errors.New("no shares provided")
	errSecretIsZero     = errors.New("the provided secret is zero")
	errTooFewShares     = errors.New("number of shares must be equal or greater than the threshold")
	errPolyIsWrongSize  = errors.New("invalid number of coefficients in polynomial")
	errPolySecretNotSet = errors.New("provided polynomial's first coefficient not set to the secret")
)

func makeKeyShare(g group.Group, id uint16, p Polynomial, groupPublicKey *group.Element) *KeyShare {
	ids := g.NewScalar().SetUInt64(uint64(id))
	yi := p.Evaluate(ids)

	return &KeyShare{
		Secret:         yi,
		GroupPublicKey: groupPublicKey,
		PublicKeyShare: PublicKeyShare{
			PublicKey:     g.Base().Multiply(yi),
			VssCommitment: nil,
			ID:            id,
			Group:         g,
		},
	}
}

// Shard splits the secret into max shares, recoverable by a subset of threshold shares. If no secret is provided, a
// new random secret is created. To use Verifiable Secret Sharing, use ShardAndCommit.
func Shard(
	g group.Group,
	secret *group.Scalar,
	threshold, max uint16,
	polynomial ...*group.Scalar,
) ([]*KeyShare, error) {
	shares, p, err := ShardReturnPolynomial(g, secret, threshold, max, polynomial...)

	for _, pi := range p {
		pi.Zero() // zero-out the polynomial, just to be sure.
	}

	return shares, err
}

// ShardAndCommit does the same as Shard but populates the returned key shares with the VssCommitment to the polynomial.
// If no secret is provided, a new random secret is created.
func ShardAndCommit(g group.Group,
	secret *group.Scalar,
	threshold, max uint16,
	polynomial ...*group.Scalar,
) ([]*KeyShare, error) {
	shares, p, err := ShardReturnPolynomial(g, secret, threshold, max, polynomial...)
	if err != nil {
		return nil, err
	}

	commitment := Commit(g, p)

	for _, share := range shares {
		share.VssCommitment = commitment
	}

	for _, pi := range p {
		pi.Zero() // zero-out the polynomial, just to be sure.
	}

	return shares, nil
}

// ShardReturnPolynomial splits the secret into max shares, recoverable by a subset of threshold shares, and returns
// the constructed secret polynomial without committing to it. If no secret is provided, a new random secret is created.
// Use the Commit function if you want to commit to the returned polynomial.
func ShardReturnPolynomial(
	g group.Group,
	secret *group.Scalar,
	threshold, max uint16,
	polynomial ...*group.Scalar,
) ([]*KeyShare, Polynomial, error) {
	if max < threshold {
		return nil, nil, errTooFewShares
	}

	p, err := makePolynomial(g, secret, threshold, polynomial...)
	if err != nil {
		return nil, nil, err
	}

	groupPublicKey := g.Base().Multiply(p[0])

	// Evaluate the polynomial for each point x=1,...,n
	secretKeyShares := make([]*KeyShare, max)

	for i := uint16(1); i <= max; i++ {
		secretKeyShares[i-1] = makeKeyShare(g, i, p, groupPublicKey)
	}

	return secretKeyShares, p, nil
}

// KeyShares is a set of KeyShares.
type KeyShares []*KeyShare

// Combine recovers the constant secret by combining the key shares.
func (k KeyShares) Combine(g group.Group) (*group.Scalar, error) {
	if len(k) == 0 {
		return nil, errNoShares
	}

	s := make([]Share, len(k))
	for i, ks := range k {
		s[i] = ks
	}

	return CombineShares(g, s)
}

// CombineShares recovers the constant secret by combining the key shares using the Share interface.
func CombineShares(g group.Group, shares []Share) (*group.Scalar, error) {
	if len(shares) == 0 {
		return nil, errNoShares
	}

	return PolynomialInterpolateConstant(g, shares)
}

func makePolynomial(g group.Group, s *group.Scalar, threshold uint16, polynomial ...*group.Scalar) (Polynomial, error) {
	if threshold == 0 {
		return nil, errThresholdIsZero
	}

	if s != nil && s.IsZero() {
		return nil, errSecretIsZero
	}

	p := NewPolynomial(threshold)

	switch len(polynomial) {
	case 0:
		i := uint16(0)

		if s != nil {
			p[0] = s.Copy()
			i++
		}

		for ; i < threshold; i++ {
			p[i] = g.NewScalar().Random()
		}
	case int(threshold):
		if s != nil && polynomial[0].Equal(s) != 1 {
			return nil, errPolySecretNotSet
		}

		if err := copyPolynomial(p, polynomial); err != nil {
			return nil, err
		}
	default:
		return nil, errPolyIsWrongSize
	}

	return p, nil
}
