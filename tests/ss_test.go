// SPDX-License-Identifier: MIT
//
// Copyright (C) 2023 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package secretsharing_test

import (
	"fmt"
	"testing"

	group "github.com/bytemare/crypto"

	secretsharing "github.com/bytemare/secret-sharing"
)

var groups = []group.Group{
	group.Ristretto255Sha512,
	group.P256Sha256,
}

func TestSecretSharing(t *testing.T) {
	threshold := uint(2)
	max := uint(3)

	for _, g := range groups {
		t.Run(g.String(), func(tt *testing.T) {
			secret := g.NewScalar().Random()

			ss, err := secretsharing.New(g, threshold)
			if err != nil {
				t.Fatal(err)
			}

			shares, _, err := ss.Shard(secret, max)

			if len(shares) != int(max) {
				t.Fatalf("expected %d shares, got %d", max, len(shares))
			}

			subset := []*secretsharing.KeyShare{
				shares[0], shares[1],
			}

			for k := 0; k <= int(max); k++ {
				recovered, err := secretsharing.Combine(g, threshold, subset)
				if err != nil {
					t.Fatal(err)
				}

				if recovered.Equal(secret) != 1 {
					t.Fatal("invalid recovered secret")
				}
			}
		})
	}
}

func TestSecretSharing_WithPolynomial(t *testing.T) {
	threshold := uint(2)

	for _, g := range groups {
		t.Run(g.String(), func(tt *testing.T) {
			polynomial := make(secretsharing.Polynomial, threshold+1)
			polynomial[0] = g.NewScalar().Random()
			polynomial[1] = g.NewScalar().Random()
			polynomial[2] = g.NewScalar().Random()

			if _, err := secretsharing.New(g, threshold, polynomial[1:]...); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if _, err := secretsharing.New(g, threshold, polynomial...); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestVerify_Shares(t *testing.T) {
	threshold := uint(2)
	max := uint(3)

	for _, g := range groups {
		t.Run(g.String(), func(tt *testing.T) {
			secret := g.NewScalar().Random()

			ss, err := secretsharing.New(g, threshold)
			if err != nil {
				t.Fatal(err)
			}

			shares, _, err := ss.Shard(secret, max)

			if len(shares) != int(max) {
				t.Fatalf("expected %d shares, got %d", max, len(shares))
			}

			for k := 0; k <= int(max); k++ {
				recovered, err := secretsharing.Combine(g, threshold, shares)
				if err != nil {
					t.Fatal(err)
				}

				if recovered.Equal(secret) != 1 {
					t.Fatal("invalid recovered secret")
				}
			}
		})
	}
}

func TestVerify_BadShares(t *testing.T) {
	threshold := uint(2)
	max := uint(3)

	for _, g := range groups {
		t.Run(g.String(), func(tt *testing.T) {
			secret := g.NewScalar().Random()

			ss, err := secretsharing.New(g, threshold)
			if err != nil {
				t.Fatal(err)
			}

			shares, polynomial, _ := ss.Shard(secret, max)
			commitments := secretsharing.Commit(g, polynomial)

			// Alter the shares
			for _, share := range shares {
				share.SecretKey.Random()
			}

			// Verify
			for _, share := range shares {
				pk := g.Base().Multiply(share.SecretKey)
				if secretsharing.Verify(g, share.Identifier, pk, commitments) {
					t.Fatalf("verification succeeded but shouldn't")
				}
			}
		})
	}
}

func TestVerify_BadCommitments(t *testing.T) {
	threshold := uint(2)
	max := uint(3)

	for _, g := range groups {
		t.Run(g.String(), func(tt *testing.T) {
			secret := g.NewScalar().Random()

			ss, err := secretsharing.New(g, threshold)
			if err != nil {
				t.Fatal(err)
			}

			shares, polynomial, _ := ss.Shard(secret, max)
			commitments := secretsharing.Commit(g, polynomial)

			// Alter the commitments
			for _, com := range commitments {
				com.Negate()
			}

			// Verify
			for _, share := range shares {
				pk := g.Base().Multiply(share.SecretKey)
				if secretsharing.Verify(g, share.Identifier, pk, commitments) {
					t.Fatalf("verification succeeded but shouldn't")
				}
			}
		})
	}
}

func TestNew_0Threshold(t *testing.T) {
	expected := "threshold is zero"
	if _, err := secretsharing.New(0, 0); err == nil || err.Error() != expected {
		t.Fatalf("expected error %q, got %q", expected, err)
	}
}

func TestShard_LowShares(t *testing.T) {
	threshold := uint(2)
	max := threshold - 1
	expected := "number of shares must be equal or greater than the threshold"

	for _, g := range groups {
		t.Run(g.String(), func(tt *testing.T) {
			secret := g.NewScalar().Random()

			ss, err := secretsharing.New(g, threshold)
			if err != nil {
				t.Fatal(err)
			}

			if _, _, err := ss.Shard(secret, max); err == nil || err.Error() != expected {
				t.Fatalf("expected error %q, got %q", expected, err)
			}
		})
	}
}

func testBadPolynomial(g group.Group, threshold, max uint, p secretsharing.Polynomial) error {
	secret := g.NewScalar().Random()

	ss, err := secretsharing.New(g, threshold, p...)
	if err != nil {
		return err
	}

	shares, polynomial, err := ss.Shard(secret, max)
	if err != nil {
		return err
	}

	commitments := secretsharing.Commit(g, polynomial)

	// Alter the commitments
	for _, com := range commitments {
		com.Negate()
	}

	// Verify
	for id, share := range shares {
		pk := g.Base().Multiply(share.SecretKey)
		if secretsharing.Verify(g, share.Identifier, pk, commitments) {
			return fmt.Errorf("verification of %d failed", id)
		}
	}

	return nil
}

func TestBadPolynomial_NilCoeff(t *testing.T) {
	threshold := uint(2)
	max := uint(3)
	expected := "the polynomial has a nil coefficient"

	for _, g := range groups {
		// Test polynomial with a nil coefficient
		polyNilCoeff := make(secretsharing.Polynomial, threshold+1)
		polyNilCoeff[0] = g.NewScalar().Random()
		polyNilCoeff[2] = g.NewScalar().Random()

		t.Run(g.String(), func(tt *testing.T) {
			if err := testBadPolynomial(g, threshold, max, polyNilCoeff); err == nil || err.Error() != expected {
				t.Fatalf("expected error %q, got %q", expected, err)
			}

			if err := testBadPolynomial(g, threshold, max, polyNilCoeff[1:]); err == nil || err.Error() != expected {
				t.Fatalf("expected error %q, got %q", expected, err)
			}
		})
	}
}

func TestBadPolynomial_ZeroCoeff(t *testing.T) {
	threshold := uint(2)
	max := uint(3)
	expected := "one of the polynomial's coefficients is zero"

	for _, g := range groups {
		// Test polynomial with a zero coefficient
		polyZeroCoeff := make(secretsharing.Polynomial, threshold+1)
		polyZeroCoeff[0] = g.NewScalar().Random()
		polyZeroCoeff[1] = g.NewScalar().Zero()
		polyZeroCoeff[2] = g.NewScalar().Random()

		t.Run(g.String(), func(tt *testing.T) {
			if err := testBadPolynomial(g, threshold, max, polyZeroCoeff); err != nil && err.Error() != expected {
				t.Fatalf("expected error %q, got %q", expected, err)
			}

			if err := testBadPolynomial(g, threshold, max, polyZeroCoeff[1:]); err != nil && err.Error() != expected {
				t.Fatalf("expected error %q, got %q", expected, err)
			}
		})
	}
}

func TestBadPolynomial_WrongSize(t *testing.T) {
	threshold := uint(2)
	max := uint(3)
	expected := "invalid number of coefficients in polynomial"

	for _, g := range groups {
		// Test polynomial with a zero coefficient
		polyShort := make(secretsharing.Polynomial, threshold-1)
		polyLong := make(secretsharing.Polynomial, threshold+2)

		t.Run(g.String(), func(tt *testing.T) {
			if err := testBadPolynomial(g, threshold, max, polyShort); err != nil && err.Error() != expected {
				t.Fatalf("expected error %q, got %q", expected, err)
			}

			if err := testBadPolynomial(g, threshold, max, polyLong); err != nil && err.Error() != expected {
				t.Fatalf("expected error %q, got %q", expected, err)
			}
		})
	}
}

func TestCombine_TooFewShares(t *testing.T) {
	threshold := uint(2)
	expected := "number of shares must be equal or greater than the threshold"

	for _, g := range groups {
		// Nil shares
		if _, err := secretsharing.Combine(g, threshold, nil); err == nil || err.Error() != expected {
			t.Fatalf("expected error %q, got %q", expected, err)
		}

		// Zero shares
		var shares []*secretsharing.KeyShare
		if _, err := secretsharing.Combine(g, threshold, shares); err == nil || err.Error() != expected {
			t.Fatalf("expected error %q, got %q", expected, err)
		}

		// Low shares
		shares = []*secretsharing.KeyShare{
			{
				Identifier: nil,
				SecretKey:  nil,
			}}
		if _, err := secretsharing.Combine(g, threshold, shares); err == nil || err.Error() != expected {
			t.Fatalf("expected error %q, got %q", expected, err)
		}
	}
}

func TestCombine_BadIdentifiers_NilZero_1(t *testing.T) {
	expected := "identifier for interpolation is nil or zero"

	for _, g := range groups {
		badShare := []*secretsharing.KeyShare{
			{
				Identifier: nil,
				SecretKey:  nil,
			},
		}
		if _, err := secretsharing.PolynomialInterpolateConstant(g, badShare); err == nil || err.Error() != expected {
			t.Fatalf("expected error %q, got %q", expected, err)
		}
	}
}

func TestCombine_BadIdentifiers_Nil(t *testing.T) {
	expected := "the polynomial has a nil coefficient"

	for _, g := range groups {

		badShare := []*secretsharing.KeyShare{
			{
				Identifier: g.NewScalar().One(),
				SecretKey:  g.NewScalar().Random(),
			},
			{
				Identifier: nil,
				SecretKey:  g.NewScalar().Random(),
			},
		}
		if _, err := secretsharing.PolynomialInterpolateConstant(g, badShare); err == nil || err.Error() != expected {
			t.Fatalf("expected error %q, got %q", expected, err)
		}
	}
}

func TestCombine_BadIdentifiers_Zero(t *testing.T) {
	expected := "one of the polynomial's coefficients is zero"

	for _, g := range groups {

		badShare := []*secretsharing.KeyShare{
			{
				Identifier: g.NewScalar().One(),
				SecretKey:  g.NewScalar().Random(),
			},
			{
				Identifier: g.NewScalar().Zero(),
				SecretKey:  g.NewScalar().Random(),
			},
		}
		if _, err := secretsharing.PolynomialInterpolateConstant(g, badShare); err == nil || err.Error() != expected {
			t.Fatalf("expected error %q, got %q", expected, err)
		}
	}
}

func TestCombine_BadIdentifiers_Duplicates(t *testing.T) {
	expected := "the polynomial has duplicate coefficients"

	for _, g := range groups {

		badShare := []*secretsharing.KeyShare{
			{
				Identifier: g.NewScalar().One(),
				SecretKey:  g.NewScalar().Random(),
			},
			{
				Identifier: g.NewScalar().One(),
				SecretKey:  g.NewScalar().Random(),
			},
		}
		if _, err := secretsharing.PolynomialInterpolateConstant(g, badShare); err == nil || err.Error() != expected {
			t.Fatalf("expected error %q, got %q", expected, err)
		}
	}
}
