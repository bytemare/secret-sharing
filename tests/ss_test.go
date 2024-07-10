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

func testCombine(g group.Group, secret *group.Scalar, shares secretsharing.KeyShares) (error, bool) {
	recovered1, err := shares.Combine(g)
	if err != nil {
		return err, false
	}

	s := make([]secretsharing.Share, len(shares))
	for i, k := range shares {
		s[i] = k
	}

	recovered, err := secretsharing.CombineShares(g, s)
	if err != nil {
		return err, false
	}

	if recovered1.Equal(recovered) != 1 {
		return errors.New("combine returned different results"), false
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
			if err, _ = testCombine(g, secret, shares[:threshold-1]); err == nil {
				t.Fatal("expected error on too few shares")
			}

			// it must succeed with threshold shares
			if err, _ = testCombine(g, secret, shares[:threshold]); err != nil {
				t.Fatalf("unexpected error on threshold number of shares: %v", err)
			}

			// it must succeed with more than threshold shares
			if err, _ = testCombine(g, secret, shares[:total]); err != nil {
				t.Fatalf("unexpected error: %s", err)
			}
		})
	}
}

func TestNewPolynomial_Ints(t *testing.T) {
	total := uint(3)

	for _, g := range groups {
		t.Run(g.String(), func(tt *testing.T) {
			pRef := secretsharing.NewPolynomial(total)
			ints := make([]uint64, total)
			shares := make([]*secretsharing.KeyShare, total)
			for i := range total {
				i64 := uint64(i + 1)
				pRef[i] = g.NewScalar().SetUInt64(i64)
				ints[i] = i64
				shares[i] = &secretsharing.KeyShare{PublicKeyShare: &secretsharing.PublicKeyShare{ID: i64}}
			}

			pInts := secretsharing.NewPolynomialFromIntegers(g, ints)
			pShares := secretsharing.NewPolynomialFromListFunc(
				g,
				shares,
				func(share *secretsharing.KeyShare) *group.Scalar {
					return g.NewScalar().SetUInt64(share.ID)
				},
			)

			for i := range total {
				if pRef[i].Equal(pInts[i]) != 1 || pRef[i].Equal(pShares[i]) != 1 {
					t.Fatal("expected equality")
				}
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
				pk := g.Base().Multiply(keyshare.Secret)
				if !secretsharing.Verify(g, keyshare.ID, pk, commitment) {
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
				share.Secret.Random()
			}

			// Verify
			for _, share := range shares {
				pk := g.Base().Multiply(share.Secret)
				if secretsharing.Verify(g, share.ID, pk, commitments) {
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
				pk := g.Base().Multiply(share.Secret)
				if secretsharing.Verify(g, share.ID, pk, commitments) {
					t.Fatalf("verification succeeded but shouldn't")
				}
			}

			// Test without commitments
			if secretsharing.Verify(g, 0, nil, nil) {
				t.Fatalf("verification succeeded but shouldn't")
			}

			if secretsharing.Verify(g, 0, nil, make(secretsharing.Commitment, 0)) {
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
		pk := g.Base().Multiply(share.Secret)
		if secretsharing.Verify(g, share.ID, pk, commitments) {
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
		if _, err := secretsharing.CombineShares(g, nil); err == nil || err.Error() != expected {
			t.Fatalf("expected error %q, got %q", expected, err)
		}

		// Zero shares
		var shares []secretsharing.Share
		if _, err := secretsharing.CombineShares(g, shares); err == nil || err.Error() != expected {
			t.Fatalf("expected error %q, got %q", expected, err)
		}
	}
}

func TestCombine_BadIdentifiers_NilZero_1(t *testing.T) {
	expected := "identifier for interpolation is nil or zero"

	for _, g := range groups {
		badShare := []secretsharing.Share{
			&secretsharing.KeyShare{
				Secret:         nil,
				PublicKeyShare: &secretsharing.PublicKeyShare{ID: 0},
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
		xCoords := secretsharing.Polynomial{g.NewScalar().SetUInt64(1), nil}
		if _, err := xCoords.DeriveInterpolatingValue(g, xCoords[0]); err == nil || err.Error() != expected {
			t.Fatalf("expected error %q, got %q", expected, err)
		}
	}
}

func TestCombine_BadIdentifiers_Zero(t *testing.T) {
	expected := "one of the polynomial's coefficients is zero"

	for _, g := range groups {

		badShare := []secretsharing.Share{
			&secretsharing.KeyShare{
				Secret:         g.NewScalar().Random(),
				PublicKeyShare: &secretsharing.PublicKeyShare{ID: 1},
			},
			&secretsharing.KeyShare{
				Secret:         g.NewScalar().Random(),
				PublicKeyShare: &secretsharing.PublicKeyShare{ID: 0},
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
		badShare := []secretsharing.Share{
			&secretsharing.KeyShare{
				Secret:         g.NewScalar().Random(),
				PublicKeyShare: &secretsharing.PublicKeyShare{ID: 1},
			},
			&secretsharing.KeyShare{
				Secret:         g.NewScalar().Random(),
				PublicKeyShare: &secretsharing.PublicKeyShare{ID: 1},
			},
		}
		if _, err := secretsharing.PolynomialInterpolateConstant(g, badShare); err == nil || err.Error() != expected {
			t.Fatalf("expected error %q, got %q", expected, err)
		}
	}
}

func TestPubKeyForCommitment(t *testing.T) {
	threshold := uint(3)    // threshold is the minimum amount of necessary shares to recombine the secret
	shareholders := uint(7) // the total amount of key share-holders

	for _, g := range groups {
		// This is the global secret to be shared
		secret := g.NewScalar().Random()

		// Shard the secret into shares
		shares, polynomial, err := secretsharing.ShardReturnPolynomial(g, secret, threshold, shareholders)
		if err != nil {
			panic(err)
		}

		commitment := secretsharing.Commit(g, polynomial)

		// No expected error
		pk, err := secretsharing.PubKeyForCommitment(g, shares[0].ID, commitment)
		if err != nil {
			t.Fatal(err)
		}

		if pk.Equal(shares[0].PublicKey) != 1 {
			t.Fatalf("unexpected public key:\n\twant: %v\n\tgot : %v\n", shares[0].PublicKey.Hex(), pk.Hex())
		}

		if !secretsharing.Verify(g, shares[0].ID, shares[0].PublicKey, commitment) {
			t.Fatal("unexpected public key")
		}
	}
}

func TestPubKeyForCommitment_Bad_CommitmentNilElement(t *testing.T) {
	errCommitmentNilElement := errors.New("commitment has nil element")
	threshold := uint(4)
	shareholders := uint(7)

	for _, g := range groups {
		secret := g.NewScalar().Random()
		shares, polynomial, err := secretsharing.ShardReturnPolynomial(g, secret, threshold, shareholders)
		if err != nil {
			panic(err)
		}

		commitment := secretsharing.Commit(g, polynomial)

		// No commitment provided
		if _, err = secretsharing.PubKeyForCommitment(g, shares[0].ID, nil); err == nil ||
			err.Error() != errCommitmentNilElement.Error() {
			t.Fatalf("expected error %q, got %q", errCommitmentNilElement, err)
		}

		// Provided commitment is empty
		if _, err = secretsharing.PubKeyForCommitment(g, shares[0].ID, []*group.Element{}); err == nil ||
			err.Error() != errCommitmentNilElement.Error() {
			t.Fatalf("expected error %q, got %q", errCommitmentNilElement, err)
		}

		// First element of commitment is nil
		if _, err = secretsharing.PubKeyForCommitment(g, shares[0].ID, []*group.Element{nil}); err == nil ||
			err.Error() != errCommitmentNilElement.Error() {
			t.Fatalf("expected error %q, got %q", errCommitmentNilElement, err)
		}

		// Second element of commitment is nil
		c := commitment[1]
		commitment[1] = nil
		if _, err = secretsharing.PubKeyForCommitment(g, shares[0].ID, commitment); err == nil ||
			err.Error() != errCommitmentNilElement.Error() {
			t.Fatalf("expected error %q, got %q", errCommitmentNilElement, err)
		}
		commitment[1] = c

		// Some other element of the commitment is nil
		commitment[3] = nil
		if _, err = secretsharing.PubKeyForCommitment(g, shares[0].ID, commitment); err == nil ||
			err.Error() != errCommitmentNilElement.Error() {
			t.Fatalf("expected error %q, got %q", errCommitmentNilElement, err)
		}
	}
}
