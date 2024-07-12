// SPDX-License-Identifier: MIT
//
// Copyright (C) 2023 Daniel Bourdrez. All Rights Reserved.
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
	errTooFewShares     = errors.New("number of shares must be equal or greater than the threshold")
	errPolyIsWrongSize  = errors.New("invalid number of coefficients in polynomial")
	errPolySecretNotSet = errors.New("provided polynomial's first coefficient not set to the secret")
)

// The Share interface enables to use functions in this package with compatible key shares.
type Share interface {
	// Identifier returns the identity for this share.
	Identifier() uint64

	// SecretKey returns the participant's secret share.
	SecretKey() *group.Scalar
}

// PublicKeyShare specifies the public key of a participant identified with ID. This can be useful to keep a registry of
// participants.
type PublicKeyShare struct {
	// The PublicKey of Secret belonging to the participant.
	PublicKey *group.Element

	// The Commitment to the polynomial the key was created with.
	Commitment []*group.Element

	// ID of the participant.
	ID uint64
}

// KeyShare holds the secret and public key share for a given participant.
type KeyShare struct {
	// The Secret of a participant (or secret share).
	Secret *group.Scalar

	// GroupPublicKey is the public key for which the secret key is sharded among participants.
	GroupPublicKey *group.Element

	// PublicKeyShare is the public part of the participant's key share.
	*PublicKeyShare
}

// Identifier returns the identity for this share.
func (s KeyShare) Identifier() uint64 {
	return s.ID
}

// SecretKey returns the participant's secret share.
func (s KeyShare) SecretKey() *group.Scalar {
	return s.Secret
}

// Public returns the public key share and identifier corresponding to the secret key share.
func (s KeyShare) Public() *PublicKeyShare {
	return s.PublicKeyShare
}

func makeKeyShare(g group.Group, id uint64, p Polynomial, groupPublicKey *group.Element) *KeyShare {
	ids := g.NewScalar().SetUInt64(id)
	yi := p.Evaluate(ids)

	return &KeyShare{
		Secret:         yi,
		GroupPublicKey: groupPublicKey,
		PublicKeyShare: &PublicKeyShare{
			PublicKey:  g.Base().Multiply(yi),
			Commitment: nil,
			ID:         id,
		},
	}
}

// Shard splits the secret into total shares, recoverable by a subset of threshold shares.
// To use Verifiable Secret Sharing, use ShardAndCommit.
func Shard(
	g group.Group,
	secret *group.Scalar,
	threshold, total uint,
	polynomial ...*group.Scalar,
) ([]*KeyShare, error) {
	shares, p, err := ShardReturnPolynomial(g, secret, threshold, total, polynomial...)

	for _, pi := range p {
		pi.Zero() // zero-out the polynomial, just to be sure.
	}

	return shares, err
}

// ShardAndCommit does the same as Shard but populates the returned key shares with the Commitment to the polynomial.
func ShardAndCommit(g group.Group,
	secret *group.Scalar,
	threshold, total uint,
	polynomial ...*group.Scalar,
) ([]*KeyShare, error) {
	shares, p, err := ShardReturnPolynomial(g, secret, threshold, total, polynomial...)
	if err != nil {
		return nil, err
	}

	commitment := Commit(g, p)

	for _, share := range shares {
		share.Commitment = commitment
	}

	for _, pi := range p {
		pi.Zero() // zero-out the polynomial, just to be sure.
	}

	return shares, nil
}

// ShardReturnPolynomial splits the secret into total shares, recoverable by a subset of threshold shares, and returns
// the constructed secret polynomial without committing to it. Use the Commit function if you want to commit to the
// returned polynomial.
func ShardReturnPolynomial(
	g group.Group,
	secret *group.Scalar,
	threshold, total uint,
	polynomial ...*group.Scalar,
) ([]*KeyShare, Polynomial, error) {
	if total < threshold {
		return nil, nil, errTooFewShares
	}

	p, err := makePolynomial(g, threshold, polynomial...)
	if err != nil {
		return nil, nil, err
	}

	if p[0] != nil && p[0].Equal(secret) == 0 {
		return nil, nil, errPolySecretNotSet
	}

	p[0] = secret.Copy()
	groupPublicKey := g.Base().Multiply(secret)

	// Evaluate the polynomial for each point x=1,...,n
	secretKeyShares := make([]*KeyShare, total)

	for i := uint64(1); i <= uint64(total); i++ {
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

func makePolynomial(g group.Group, threshold uint, polynomial ...*group.Scalar) (Polynomial, error) {
	if threshold == 0 {
		return nil, errThresholdIsZero
	}

	p := NewPolynomial(threshold)

	switch len(polynomial) {
	case 0:
		for i := uint(1); i < threshold; i++ {
			p[i] = g.NewScalar().Random()
		}
	case int(threshold - 1):
		if err := copyPolynomial(p[1:], polynomial); err != nil {
			return nil, err
		}
	case int(threshold):
		if err := copyPolynomial(p, polynomial); err != nil {
			return nil, err
		}
	default:
		return nil, errPolyIsWrongSize
	}

	return p, nil
}
