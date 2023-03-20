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
	"math/big"

	group "github.com/bytemare/crypto"
)

var (
	errThresholdIsZero = errors.New("threshold is zero")
	errTooFewShares    = errors.New("number of shares must be equal or greater than the threshold")
	errPolyIsWrongSize = errors.New("invalid number of coefficients in polynomial")
)

// KeyShare identifies the sharded key share for a given participant.
type KeyShare struct {
	// Identifier uniquely identifies a key share within secret sharing instance.
	Identifier *group.Scalar

	// SecretKey is the participant's secret share.
	SecretKey *group.Scalar
}

// SecretSharing represents an instance of Shamir's secret sharing with a threshold among n maximum participants.
type SecretSharing struct {
	polynomial Polynomial
	threshold  uint
	group      group.Group
}

// New returns a SecretSharing instance set for the given group and threshold. If the secret polynomial is given it will
// set the instance to that polynomial. If not, it will generate one with random coefficients in the group.
func New(g group.Group, threshold uint, polynomial ...*group.Scalar) (*SecretSharing, error) {
	if threshold == 0 {
		return nil, errThresholdIsZero
	}

	sharing := &SecretSharing{
		group:      g,
		threshold:  threshold,
		polynomial: NewPolynomial(threshold + 1),
	}

	switch len(polynomial) {
	case 0:
		for i := uint(1); i < threshold; i++ {
			sharing.polynomial[i] = g.NewScalar().Random()
		}
	case int(threshold):
		if err := copyPolynomial(sharing.polynomial[1:], polynomial); err != nil {
			return nil, err
		}
	case int(threshold + 1):
		if err := copyPolynomial(sharing.polynomial, polynomial); err != nil {
			return nil, err
		}
	default:
		return nil, errPolyIsWrongSize
	}

	return sharing, nil
}

// integerToScalar creates a group.Scalar given an int.
func integerToScalar(g group.Group, i uint) *group.Scalar {
	s := g.NewScalar()
	if err := s.SetInt(big.NewInt(int64(i))); err != nil {
		panic(err)
	}

	return s
}

// Shard splits the secret into nShares shares, and returns them as well as the polynomial's coefficients
// prepended by the secret.
func (s SecretSharing) Shard(secret *group.Scalar, nShares uint) ([]*KeyShare, Polynomial, error) {
	if nShares < s.threshold {
		return nil, nil, errTooFewShares
	}

	// Prepend the secret to the coefficients
	s.polynomial[0] = secret.Copy()

	// Evaluate the polynomial for each point x=1,...,n
	secretKeyShares := make([]*KeyShare, nShares)

	for i := uint(1); i <= nShares; i++ {
		id := integerToScalar(s.group, i)
		yi := s.polynomial.Evaluate(s.group, id)
		secretKeyShares[i-1] = &KeyShare{id, yi}
	}

	return secretKeyShares, s.polynomial, nil
}

// Combine recovers the constant secret by combining the key shares.
func Combine(g group.Group, threshold uint, shares []*KeyShare) (*group.Scalar, error) {
	if uint(len(shares)) < threshold {
		return nil, errTooFewShares
	}

	return PolynomialInterpolateConstant(g, shares)
}
