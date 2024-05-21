// SPDX-License-Identifier: MIT
//
// Copyright (C) 2023 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package secretsharing_test

import (
	"errors"
	"fmt"
	"testing"

	group "github.com/bytemare/crypto"

	secretsharing "github.com/bytemare/secret-sharing"
)

var groups = []group.Group{
	group.Ristretto255Sha512,
	group.P256Sha256,
	group.Secp256k1,
}

func testCombine(g group.Group, secret *group.Scalar, shares ...*secretsharing.KeyShare) (error, bool) {
	recovered, err := secretsharing.Combine(g, shares)
	if err != nil {
		return err, false
	}

	if recovered.Equal(secret) != 1 {
		return errors.New("invalid recovered secret"), false
	}

	return nil, true
}

func TestSecretSharing(t *testing.T) {
	threshold := uint(3)
	total := uint(5)

	for _, g := range groups {
		t.Run(g.String(), func(tt *testing.T) {
			secret := g.NewScalar().Random()

			shares, err := secretsharing.Shard(g, secret, threshold, total)
			if err != nil {
				t.Fatal(err)
			}

			if len(shares) != int(total) {
				t.Fatalf("expected %d shares, got %d", total, len(shares))
			}

			// it must not succeed with fewer than threshold shares
			if err, _ = testCombine(g, secret, shares[0], shares[1]); err == nil {
				t.Fatal("expected error on too few shares")
			}

			// it must not succeed with threshold shares
			if err, _ = testCombine(g, secret, shares[0], shares[1], shares[3]); err != nil {
				t.Fatal("expected error on too few shares")
			}

			// it must succeed with more than threshold shares
			if err, _ = testCombine(g, secret, shares[1], shares[3], shares[0], shares[2]); err != nil {
				t.Fatalf("unexpected error: %s", err)
			}
		})
	}
}

func TestSecretSharing_WithPolynomial(t *testing.T) {
	threshold := uint(2)
	total := uint(3)

	for _, g := range groups {
		t.Run(g.String(), func(tt *testing.T) {
			secret := g.NewScalar().Random()
			polynomial := make(secretsharing.Polynomial, threshold)
			polynomial[0] = secret
			polynomial[1] = g.NewScalar().Random()

			// Either provide the random elements of the polynomial without the prepending secret
			if _, err := secretsharing.Shard(g, secret, threshold, total, polynomial[1:]...); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			// Or provide the all elements of the polynomial with the prepending secret
			if _, err := secretsharing.Shard(g, secret, threshold, total, polynomial...); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestCommitment(t *testing.T) {
	threshold := uint(3)
	total := uint(5)

	for _, g := range groups {
		t.Run(g.String(), func(tt *testing.T) {
			secret := g.NewScalar().Random()

			shares, polynomial, err := secretsharing.ShardReturnPolynomial(g, secret, threshold, total)
			if err != nil {
				t.Fatal(err)
			}

			commitment := secretsharing.Commit(g, polynomial)

			for i, keyshare := range shares {
				pk := g.Base().Multiply(keyshare.SecretKey)
				if !secretsharing.Verify(g, keyshare.Identifier, pk, commitment) {
					t.Fatalf("invalid public key for shareholder %d", i)
				}
			}
		})
	}
}

func TestVerify_BadShares(t *testing.T) {
	threshold := uint(2)
	total := uint(3)

	for _, g := range groups {
		t.Run(g.String(), func(tt *testing.T) {
			secret := g.NewScalar().Random()

			shares, polynomial, err := secretsharing.ShardReturnPolynomial(g, secret, threshold, total)
			if err != nil {
				t.Fatal(err)
			}

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
	total := uint(3)

	for _, g := range groups {
		t.Run(g.String(), func(tt *testing.T) {
			secret := g.NewScalar().Random()

			shares, polynomial, err := secretsharing.ShardReturnPolynomial(g, secret, threshold, total)
			if err != nil {
				t.Fatal(err)
			}

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

			// Test without commitments
			if secretsharing.Verify(g, nil, nil, nil) {
				t.Fatalf("verification succeeded but shouldn't")
			}

			if secretsharing.Verify(g, nil, nil, make(secretsharing.Commitment, 0)) {
				t.Fatalf("verification succeeded but shouldn't")
			}
		})
	}
}

func TestNew_0Threshold(t *testing.T) {
	expected := "threshold is zero"
	if _, err := secretsharing.Shard(0, nil, 0, 0); err == nil || err.Error() != expected {
		t.Fatalf("expected error %q, got %q", expected, err)
	}
}

func TestShard_LowShares(t *testing.T) {
	threshold := uint(2)
	total := threshold - 1
	expected := "number of shares must be equal or greater than the threshold"

	for _, g := range groups {
		t.Run(g.String(), func(tt *testing.T) {
			secret := g.NewScalar().Random()

			if _, err := secretsharing.Shard(g, secret, threshold, total); err == nil || err.Error() != expected {
				t.Fatalf("expected error %q, got %q", expected, err)
			}
		})
	}
}

func testBadPolynomial(g group.Group, threshold, max uint, p secretsharing.Polynomial) error {
	secret := g.NewScalar().Random()

	shares, polynomial, err := secretsharing.ShardReturnPolynomial(g, secret, threshold, max, p...)
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

func TestBadPolynomial_SecretNotSet(t *testing.T) {
	threshold := uint(3)
	total := uint(5)
	expected := "provided polynomial's first coefficient not set to the secret"

	for _, g := range groups {
		// Test polynomial with first coefficient not set to the secret
		polyNoSecret := make(secretsharing.Polynomial, threshold)
		polyNoSecret[0] = g.NewScalar().Random()
		polyNoSecret[1] = g.NewScalar().Random()
		polyNoSecret[2] = g.NewScalar().Random()

		t.Run(g.String(), func(tt *testing.T) {
			if err := testBadPolynomial(g, threshold, total, polyNoSecret); err == nil || err.Error() != expected {
				t.Fatalf("expected error %q, got %q", expected, err)
			}
		})
	}
}

func TestBadPolynomial_NilCoeff(t *testing.T) {
	threshold := uint(3)
	total := uint(5)
	expected := "the polynomial has a nil coefficient"

	for _, g := range groups {
		// Test polynomial with a nil coefficient
		polyNilCoeff := make(secretsharing.Polynomial, threshold)
		polyNilCoeff[0] = g.NewScalar().Random()
		polyNilCoeff[1] = nil
		polyNilCoeff[2] = g.NewScalar().Random()

		t.Run(g.String(), func(tt *testing.T) {
			if err := testBadPolynomial(g, threshold, total, polyNilCoeff); err == nil || err.Error() != expected {
				t.Fatalf("expected error %q, got %q", expected, err)
			}

			if err := testBadPolynomial(g, threshold, total, polyNilCoeff[1:]); err == nil || err.Error() != expected {
				t.Fatalf("expected error %q, got %q", expected, err)
			}
		})
	}
}

func TestBadPolynomial_ZeroCoeff(t *testing.T) {
	threshold := uint(3)
	total := uint(5)
	expected := "one of the polynomial's coefficients is zero"

	for _, g := range groups {
		// Test polynomial with a zero coefficient
		polyZeroCoeff := make(secretsharing.Polynomial, threshold)
		polyZeroCoeff[0] = g.NewScalar().Random()
		polyZeroCoeff[1] = g.NewScalar().Zero()
		polyZeroCoeff[2] = g.NewScalar().Random()

		t.Run(g.String(), func(tt *testing.T) {
			if err := testBadPolynomial(g, threshold, total, polyZeroCoeff); err != nil && err.Error() != expected {
				t.Fatalf("expected error %q, got %q", expected, err)
			}

			if err := testBadPolynomial(g, threshold, total, polyZeroCoeff[1:]); err != nil && err.Error() != expected {
				t.Fatalf("expected error %q, got %q", expected, err)
			}
		})
	}
}

func TestBadPolynomial_WrongSize(t *testing.T) {
	threshold := uint(2)
	total := uint(3)
	expected := "invalid number of coefficients in polynomial"

	for _, g := range groups {
		// Test polynomial with a zero coefficient
		polyShort := secretsharing.Polynomial{
			g.NewScalar().Random(),
		} // threshold-1
		polyLong := secretsharing.Polynomial{
			g.NewScalar().Random(),
			g.NewScalar().Random(),
			g.NewScalar().Random(),
		} // threshold+2

		t.Run(g.String(), func(tt *testing.T) {
			if err := testBadPolynomial(g, threshold, total, polyShort); err != nil && err.Error() != expected {
				t.Fatalf("expected error %q, got %q", expected, err)
			}

			if err := testBadPolynomial(g, threshold, total, polyLong); err != nil && err.Error() != expected {
				t.Fatalf("expected error %q, got %q", expected, err)
			}
		})
	}
}

func TestCombine_TooFewShares(t *testing.T) {
	// threshold := uint(2)
	expected := "no shares provided"

	for _, g := range groups {
		// Nil shares
		if _, err := secretsharing.Combine(g, nil); err == nil || err.Error() != expected {
			t.Fatalf("expected error %q, got %q", expected, err)
		}

		// Zero shares
		var shares []*secretsharing.KeyShare
		if _, err := secretsharing.Combine(g, shares); err == nil || err.Error() != expected {
			t.Fatalf("expected error %q, got %q", expected, err)
		}

		// Low shares - not tested since we don't keep trace of the threshold anymore
		//shares = []*secretsharing.KeyShare{
		//	{
		//		Identifier: nil,
		//		SecretKey:  nil,
		//	}}
		//if _, err := secretsharing.Combine(g, shares); err == nil || err.Error() != expected {
		//	t.Fatalf("expected error %q, got %q", expected, err)
		//}
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
