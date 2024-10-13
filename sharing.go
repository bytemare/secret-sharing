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

	"github.com/bytemare/ecc"

	"github.com/bytemare/secret-sharing/keys"
)

var (
	errThresholdIsZero  = errors.New("threshold is zero")
	errNoShares         = errors.New("no shares provided")
	errSecretIsZero     = errors.New("the provided secret is zero")
	errTooFewShares     = errors.New("number of shares must be equal or greater than the threshold")
	errPolyIsWrongSize  = errors.New("invalid number of coefficients in polynomial")
	errPolySecretNotSet = errors.New("provided polynomial's first coefficient not set to the secret")
	errMultiGroup       = errors.New("incompatible EC groups found in set of key shares")
)

func makeKeyShare(g ecc.Group, id uint16, p Polynomial, verificationKey *ecc.Element, c VssCommitment) *keys.KeyShare {
	ids := g.NewScalar().SetUInt64(uint64(id))
	yi := p.Evaluate(ids)

	return &keys.KeyShare{
		Secret:          yi,
		VerificationKey: verificationKey,
		PublicKeyShare: keys.PublicKeyShare{
			PublicKey:     g.Base().Multiply(yi),
			VssCommitment: c,
			ID:            id,
			Group:         g,
		},
	}
}

func innerShard(g ecc.Group,
	secret *ecc.Scalar,
	threshold, max uint16,
	commit, returnPoly bool,
	polynomial ...*ecc.Scalar,
) ([]*keys.KeyShare, Polynomial, error) {
	if max < threshold {
		return nil, nil, errTooFewShares
	}

	p, err := makePolynomial(g, secret, threshold, polynomial...)
	if err != nil {
		return nil, nil, err
	}

	var commitment VssCommitment
	var verificationKey *ecc.Element

	if commit {
		commitment = Commit(g, p)
		verificationKey = commitment[0]
	} else {
		verificationKey = g.Base().Multiply(p[0])
	}

	// Evaluate the polynomial for each point x=1,...,n
	secretKeyShares := make([]*keys.KeyShare, max)

	for i := uint16(1); i <= max; i++ {
		secretKeyShares[i-1] = makeKeyShare(g, i, p, verificationKey, commitment)
	}

	if returnPoly {
		return secretKeyShares, p, nil
	}

	for _, pi := range p {
		pi.Zero() // zero-out the polynomial, just to be sure.
	}

	return secretKeyShares, nil, nil
}

// Shard splits the secret into max shares, recoverable by a subset of threshold shares. If no secret is provided, a
// new random secret is created. To use Verifiable Secret Sharing, use ShardAndCommit.
func Shard(
	g ecc.Group,
	secret *ecc.Scalar,
	threshold, max uint16,
	polynomial ...*ecc.Scalar,
) ([]*keys.KeyShare, error) {
	shares, _, err := innerShard(g, secret, threshold, max, false, false, polynomial...)
	return shares, err
}

// ShardAndCommit does the same as Shard but populates the returned key shares with the VssCommitment to the polynomial.
// If no secret is provided, a new random secret is created.
func ShardAndCommit(g ecc.Group,
	secret *ecc.Scalar,
	threshold, max uint16,
	polynomial ...*ecc.Scalar,
) ([]*keys.KeyShare, error) {
	shares, _, err := innerShard(g, secret, threshold, max, true, false, polynomial...)
	return shares, err
}

// ShardReturnPolynomial splits the secret into max shares, recoverable by a subset of threshold shares, and returns
// the constructed secret polynomial without committing to it. If no secret is provided, a new random secret is created.
// Use the Commit function if you want to commit to the returned polynomial.
func ShardReturnPolynomial(
	g ecc.Group,
	secret *ecc.Scalar,
	threshold, max uint16,
	polynomial ...*ecc.Scalar,
) ([]*keys.KeyShare, Polynomial, error) {
	return innerShard(g, secret, threshold, max, false, true, polynomial...)
}

// CombineShares recovers the sharded secret by combining the key shares that implement the Share interface. It recovers
// the constant term of the interpolating polynomial defined by the set of key shares.
func CombineShares(shares []*keys.KeyShare) (*ecc.Scalar, error) {
	if len(shares) == 0 {
		return nil, errNoShares
	}

	g := shares[0].Group()

	xCoords := NewPolynomialFromListFunc(g, shares, func(share *keys.KeyShare) *ecc.Scalar {
		return g.NewScalar().SetUInt64(uint64(share.Identifier()))
	})

	key := g.NewScalar().Zero()

	for i, share := range shares {
		if share.Group() != g {
			return nil, errMultiGroup
		}

		iv, err := xCoords.DeriveInterpolatingValue(g, xCoords[i])
		if err != nil {
			return nil, err
		}

		delta := iv.Multiply(share.SecretKey())
		key.Add(delta)
	}

	return key, nil
}

func makePolynomial(g ecc.Group, s *ecc.Scalar, threshold uint16, polynomial ...*ecc.Scalar) (Polynomial, error) {
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
		if s != nil && !polynomial[0].Equal(s) {
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
