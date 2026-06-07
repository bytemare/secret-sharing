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
	"fmt"

	"github.com/bytemare/ecc"

	"github.com/bytemare/secret-sharing/keys"
)

var (
	errThresholdIsZero    = errors.New("threshold is zero")
	errNoShares           = errors.New("no shares provided")
	errSecretIsZero       = errors.New("the provided secret is zero")
	errTooFewShares       = errors.New("number of shares must be equal or greater than the threshold")
	errPolyIsWrongSize    = errors.New("invalid number of coefficients in polynomial")
	errPolySecretNotSet   = errors.New("provided polynomial's first coefficient not set to the secret")
	errMultiGroup         = errors.New("incompatible EC groups found in set of key shares")
	errInvalidGroup       = errors.New("invalid EC group")
	errInvalidScalar      = errors.New("invalid scalar")
	errScalarGroup        = errors.New("scalar has incompatible EC group")
	errNilShare           = errors.New("key share is nil")
	errNilRegistry        = errors.New("public key share registry is nil")
	errInvalidRegistry    = errors.New("invalid public key share registry")
	errInvalidKeyShare    = errors.New("invalid key share")
	errMalformedCrypto    = errors.New("malformed cryptographic input")
	errShareNotRegistered = errors.New("key share does not match registry")
)

func makeKeyShare(
	g ecc.Group,
	id uint16,
	p Polynomial,
	verificationKey *ecc.Element,
	c VssCommitment,
) (*keys.KeyShare, error) {
	ids := g.NewScalar().SetUInt64(uint64(id))
	yi := p.Evaluate(ids)

	ks, err := keys.NewKeyShare(g, id, yi, verificationKey, c)
	if err != nil {
		return nil, fmt.Errorf("failed to create key share: %w", err)
	}

	return ks, nil
}

func innerShard(g ecc.Group,
	secret *ecc.Scalar,
	threshold, maximum uint16,
	commit, returnPoly bool,
	polynomial ...*ecc.Scalar,
) (shares []*keys.KeyShare, returnedPolynomial Polynomial, err error) {
	defer func() {
		if recover() != nil {
			shares = nil
			returnedPolynomial = nil
			err = errMalformedCrypto
		}
	}()

	if maximum < threshold {
		return nil, nil, errTooFewShares
	}

	p, err := makePolynomial(g, secret, threshold, polynomial...)
	if err != nil {
		return nil, nil, err
	}

	wipePolynomial := true

	defer func() {
		if wipePolynomial {
			zeroPolynomial(p)
		}
	}()

	var (
		commitment      VssCommitment
		verificationKey *ecc.Element
	)

	if commit {
		commitment, err = Commit(g, p)
		if err != nil {
			return nil, nil, err
		}

		verificationKey = commitment[0]
	} else {
		verificationKey = g.Base().Multiply(p[0])
	}

	// Evaluate the polynomial for each point x=1,...,n
	secretKeyShares := make([]*keys.KeyShare, maximum)

	for i := uint16(1); i <= maximum; i++ {
		secretKeyShares[i-1], err = makeKeyShare(g, i, p, verificationKey, commitment)
		if err != nil {
			return nil, nil, err
		}
	}

	if returnPoly {
		wipePolynomial = false
		return secretKeyShares, p, nil
	}

	return secretKeyShares, nil, nil
}

// Shard splits the secret into max shares, recoverable by a subset of threshold shares. If no secret is provided, a
// new random secret is created. To use Verifiable Secret Sharing, use ShardAndCommit.
func Shard(
	g ecc.Group,
	secret *ecc.Scalar,
	threshold, maximum uint16,
	polynomial ...*ecc.Scalar,
) ([]*keys.KeyShare, error) {
	shares, _, err := innerShard(g, secret, threshold, maximum, false, false, polynomial...)
	return shares, err
}

// ShardAndCommit does the same as Shard but populates the returned key shares with the VssCommitment to the polynomial.
// If no secret is provided, a new random secret is created.
func ShardAndCommit(g ecc.Group,
	secret *ecc.Scalar,
	threshold, maximum uint16,
	polynomial ...*ecc.Scalar,
) ([]*keys.KeyShare, error) {
	shares, _, err := innerShard(g, secret, threshold, maximum, true, false, polynomial...)
	return shares, err
}

// ShardReturnPolynomial splits the secret into max shares, recoverable by a subset of threshold shares, and returns
// the constructed secret polynomial without committing to it. If no secret is provided, a new random secret is created.
// Use the Commit function if you want to commit to the returned polynomial.
func ShardReturnPolynomial(
	g ecc.Group,
	secret *ecc.Scalar,
	threshold, maximum uint16,
	polynomial ...*ecc.Scalar,
) ([]*keys.KeyShare, Polynomial, error) {
	return innerShard(g, secret, threshold, maximum, false, true, polynomial...)
}

// ShardAndCommitAndReturnPolynomial splits the secret into max shares, recoverable by a subset of threshold shares,
// and returns the constructed secret polynomial. Each KeyShare holds the commitment to that polynomial. If no secret is
// provided, a new random secret is created.
func ShardAndCommitAndReturnPolynomial(
	g ecc.Group,
	secret *ecc.Scalar,
	threshold, maximum uint16,
	polynomial ...*ecc.Scalar,
) ([]*keys.KeyShare, Polynomial, error) {
	return innerShard(g, secret, threshold, maximum, true, true, polynomial...)
}

// CombineShares recovers the sharded secret by combining at least threshold key shares. It recovers the constant term
// of the interpolating polynomial defined by the set of key shares.
func CombineShares(shares []*keys.KeyShare, threshold uint16) (*ecc.Scalar, error) {
	if threshold == 0 {
		return nil, errThresholdIsZero
	}

	if len(shares) == 0 {
		return nil, errNoShares
	}

	if len(shares) < int(threshold) {
		return nil, errTooFewShares
	}

	g, err := validateSharesForReconstruction(shares)
	if err != nil {
		return nil, err
	}

	xCoords, err := NewPolynomialFromListFunc(g, shares, func(share *keys.KeyShare) *ecc.Scalar {
		return g.NewScalar().SetUInt64(uint64(share.Identifier()))
	})
	if err != nil {
		return nil, err
	}

	if len(xCoords) != len(shares) {
		return nil, errInvalidScalar
	}

	return combineShares(g, shares, xCoords)
}

func combineShares(g ecc.Group, shares []*keys.KeyShare, xCoords Polynomial) (key *ecc.Scalar, err error) {
	defer func() {
		if recover() != nil {
			key = nil
			err = errMalformedCrypto
		}
	}()

	key = g.NewScalar().Zero()

	for i, share := range shares {
		var iv *ecc.Scalar

		iv, err = xCoords.DeriveInterpolatingValue(g, xCoords[i])
		if err != nil {
			return nil, err
		}

		ivGroup, ok := polynomialScalarGroup(iv)
		if !ok {
			return nil, errInvalidScalar
		}

		if ivGroup != g {
			return nil, errScalarGroup
		}

		secret := share.SecretKey()

		secretGroup, ok := polynomialScalarGroup(secret)
		if !ok {
			return nil, errInvalidScalar
		}

		if secretGroup != g {
			return nil, errScalarGroup
		}

		delta := iv.Multiply(secret)
		key.Add(delta)
	}

	return key, nil
}

// CombineVerifiedShares verifies the registry and key shares before reconstructing the secret.
func CombineVerifiedShares(
	registry *keys.PublicKeyShareRegistry,
	shares []*keys.KeyShare,
) (secret *ecc.Scalar, err error) {
	defer func() {
		if recover() != nil {
			secret = nil
			err = errMalformedCrypto
		}
	}()

	if err = validateRegistryForReconstruction(registry); err != nil {
		return nil, err
	}

	for _, share := range shares {
		if err = validateRegisteredKeyShare(registry, share); err != nil {
			return nil, err
		}
	}

	return CombineShares(shares, registry.Threshold())
}

func makePolynomial(g ecc.Group, s *ecc.Scalar, threshold uint16, polynomial ...*ecc.Scalar) (Polynomial, error) {
	if threshold == 0 {
		return nil, errThresholdIsZero
	}

	if !g.Available() {
		return nil, errInvalidGroup
	}

	if s != nil {
		if !scalarInGroup(s, g) {
			return nil, errScalarGroup
		}

		if s.IsZero() {
			return nil, errSecretIsZero
		}
	}

	p := NewPolynomial(threshold)

	switch len(polynomial) {
	case 0:
		return makePolynomial0(g, s, p, threshold), nil
	case int(threshold):
		return makePolynomialCore(g, s, p, polynomial)
	default:
		return nil, errPolyIsWrongSize
	}
}

func makePolynomial0(g ecc.Group, s *ecc.Scalar, p Polynomial, threshold uint16) Polynomial {
	i := uint16(0)

	if s != nil {
		p[0] = s.Copy()
		i++
	}

	for ; i < threshold; i++ {
		p[i] = g.NewScalar().Random()
	}

	return p
}

func makePolynomialCore(g ecc.Group, s *ecc.Scalar, p, polynomial Polynomial) (Polynomial, error) {
	for _, coefficient := range polynomial {
		if coefficient != nil && !scalarInGroup(coefficient, g) {
			zeroPolynomial(p)
			return nil, errScalarGroup
		}
	}

	if err := copyPolynomial(p, polynomial); err != nil {
		zeroPolynomial(p)
		return nil, err
	}

	if s != nil && !polynomial[0].Equal(s) {
		zeroPolynomial(p)
		return nil, errPolySecretNotSet
	}

	return p, nil
}

func zeroPolynomial(p Polynomial) {
	for i, coefficient := range p {
		if coefficient != nil {
			coefficient.Zero()
		}

		p[i] = nil
	}
}

func scalarInGroup(s *ecc.Scalar, g ecc.Group) (ok bool) {
	if s == nil || !g.Available() {
		return false
	}

	defer func() {
		if recover() != nil {
			ok = false
		}
	}()

	return s.Group() == g
}

func validateSharesForReconstruction(shares []*keys.KeyShare) (ecc.Group, error) {
	var g ecc.Group

	ids := make(map[uint16]struct{}, len(shares))

	for i, share := range shares {
		if share == nil {
			return 0, errNilShare
		}

		id := share.Identifier()
		if id == 0 {
			return 0, errPolyXIsZero
		}

		if _, ok := ids[id]; ok {
			return 0, errPolyHasDuplicates
		}

		ids[id] = struct{}{}

		shareGroup := share.Group()
		if !shareGroup.Available() {
			return 0, errInvalidGroup
		}

		if i == 0 {
			g = shareGroup
		} else if shareGroup != g {
			return 0, errMultiGroup
		}

		if share.SecretKey() == nil {
			return 0, errInvalidScalar
		}

		if !scalarInGroup(share.SecretKey(), g) {
			return 0, errScalarGroup
		}
	}

	return g, nil
}

func validateRegistryForReconstruction(registry *keys.PublicKeyShareRegistry) error {
	if registry == nil {
		return errNilRegistry
	}

	if err := registry.Validate(); err != nil {
		return fmt.Errorf("%w: %w", errInvalidRegistry, err)
	}

	return nil
}

func validateRegisteredKeyShare(registry *keys.PublicKeyShareRegistry, share *keys.KeyShare) error {
	if share == nil {
		return errNilShare
	}

	id := share.Identifier()
	if id == 0 || id > registry.Total() || share.Group() != registry.Group() {
		return errInvalidKeyShare
	}

	if err := share.Validate(); err != nil {
		return fmt.Errorf("%w: %w", errInvalidKeyShare, err)
	}

	verificationKey := share.VerificationKey()
	commitment := share.PublicKeyShare().Commitment()

	if !verificationKey.Equal(registry.VerificationKey()) ||
		len(commitment) != int(registry.Threshold()) ||
		!VerifyPublicKeyShare(share.PublicKeyShare()) {
		return errInvalidKeyShare
	}

	registered := registry.Get(id)
	public := share.PublicKeyShare()

	if registered == nil ||
		!registered.PublicKey().Equal(public.PublicKey()) ||
		!commitmentsEqual(registered.Commitment(), commitment) {
		return errShareNotRegistered
	}

	return nil
}

func commitmentsEqual(left, right []*ecc.Element) bool {
	if len(left) != len(right) {
		return false
	}

	for i := range left {
		if !left[i].Equal(right[i]) {
			return false
		}
	}

	return true
}
