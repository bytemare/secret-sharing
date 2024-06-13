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

// KeyShare identifies the sharded key share for a given participant.
type KeyShare struct {
	// SecretKey is the participant's secret share.
	SecretKey *group.Scalar

	// Identifier uniquely identifies a key share within secret sharing instance.
	Identifier uint64
}

// Shard splits the secret into total shares, recoverable by a subset of threshold shares. This is the function you
// should probably use.
func Shard(
	g group.Group,
	secret *group.Scalar,
	threshold, total uint,
	polynomial ...*group.Scalar,
) ([]*KeyShare, error) {
	shares, p, err := ShardReturnPolynomial(g, secret, threshold, total, polynomial...)

	for _, pi := range p {
		pi.Zero() // zero-out the polynomial, juste to be sure
	}

	return shares, err
}

// ShardReturnPolynomial splits the secret into total shares, recoverable by a subset of threshold shares, and returns
// the constructed polynomial. Unless you know what you are doing, you probably want to use Shard() instead.
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

	// Evaluate the polynomial for each point x=1,...,n
	secretKeyShares := make([]*KeyShare, total)

	for i := uint64(1); i <= uint64(total); i++ {
		id := g.NewScalar().SetUInt64(i)
		yi := p.Evaluate(id)
		secretKeyShares[i-1] = &KeyShare{Identifier: i, SecretKey: yi}
	}

	return secretKeyShares, p, nil
}

// Combine recovers the constant secret by combining the key shares.
func Combine(g group.Group, shares []*KeyShare) (*group.Scalar, error) {
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
