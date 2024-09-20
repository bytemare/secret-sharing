// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package secretsharing_test

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"
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
	threshold := uint16(3)
	max := uint16(5)

	for _, g := range groups {
		t.Run(g.String(), func(t *testing.T) {
			secret := g.NewScalar().Random()

			shares, err := secretsharing.Shard(g, secret, threshold, max)
			if err != nil {
				t.Fatal(err)
			}

			if len(shares) != int(max) {
				t.Fatalf("expected %d shares, got %d", max, len(shares))
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
			if err, _ = testCombine(g, secret, shares[:max]); err != nil {
				t.Fatalf("unexpected error: %s", err)
			}
		})
	}
}

func TestNewPolynomial_Ints(t *testing.T) {
	max := uint16(3)

	for _, g := range groups {
		t.Run(g.String(), func(tt *testing.T) {
			pRef := secretsharing.NewPolynomial(max)
			ints := make([]uint16, max)
			shares := make([]*secretsharing.KeyShare, max)
			for i := range max {
				id := i + 1
				pRef[i] = g.NewScalar().SetUInt64(uint64(id))
				ints[i] = id
				shares[i] = &secretsharing.KeyShare{PublicKeyShare: secretsharing.PublicKeyShare{ID: id}}
			}

			pInts := secretsharing.NewPolynomialFromIntegers(g, ints)
			pShares := secretsharing.NewPolynomialFromListFunc(
				g,
				shares,
				func(share *secretsharing.KeyShare) *group.Scalar {
					return g.NewScalar().SetUInt64(uint64(share.ID))
				},
			)

			for i := range max {
				if pRef[i].Equal(pInts[i]) != 1 || pRef[i].Equal(pShares[i]) != 1 {
					t.Fatal("expected equality")
				}
			}
		})
	}
}

func TestSecretSharing_WithPolynomial(t *testing.T) {
	threshold := uint16(2)
	max := uint16(3)

	for _, g := range groups {
		t.Run(g.String(), func(tt *testing.T) {
			secret := g.NewScalar().Random()
			polynomial := make(secretsharing.Polynomial, threshold)
			polynomial[0] = secret
			polynomial[1] = g.NewScalar().Random()

			// Provide the all elements of the polynomial with the prepending secret
			if _, err := secretsharing.Shard(g, secret, threshold, max, polynomial...); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestCommitment(t *testing.T) {
	threshold := uint16(3)
	max := uint16(5)

	for _, g := range groups {
		t.Run(g.String(), func(tt *testing.T) {
			secret := g.NewScalar().Random()

			shares, err := secretsharing.ShardAndCommit(g, secret, threshold, max)
			if err != nil {
				t.Fatal(err)
			}

			for i, keyshare := range shares {
				pk := g.Base().Multiply(keyshare.Secret)

				pubkey := keyshare.Public()
				if pk.Equal(pubkey.PublicKey) != 1 {
					t.Fatal("expected equality")
				}

				if !pubkey.Verify() {
					t.Fatalf("invalid public key for shareholder %d", i)
				}

				if !secretsharing.Verify(g, pubkey.ID, pk, pubkey.Commitment) {
					t.Fatalf("invalid public key for shareholder %d", i)
				}
			}

			b, err := json.Marshal(shares[0])
			if err != nil {
				t.Fatal(err)
			}

			k := secretsharing.KeyShare{}
			if err := json.Unmarshal(b, &k); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCombine_Bad_NoKeys(t *testing.T) {
	errNoShares := errors.New("no shares provided")

	for _, g := range groups {
		t.Run(g.String(), func(tt *testing.T) {
			shares := secretsharing.KeyShares{}

			if _, err := shares.Combine(g); err == nil || err.Error() != errNoShares.Error() {
				t.Fatal("expected error")
			}

			shares2 := []secretsharing.Share{}

			if _, err := secretsharing.CombineShares(g, nil); err == nil || err.Error() != errNoShares.Error() {
				t.Fatal("expected error")
			}

			if _, err := secretsharing.CombineShares(g, shares2); err == nil || err.Error() != errNoShares.Error() {
				t.Fatal("expected error")
			}
		})
	}
}

func TestVerify_BadShares(t *testing.T) {
	threshold := uint16(2)
	max := uint16(3)

	for _, g := range groups {
		t.Run(g.String(), func(tt *testing.T) {
			secret := g.NewScalar().Random()

			shares, err := secretsharing.ShardAndCommit(g, secret, threshold, max)
			if err != nil {
				t.Fatal(err)
			}

			// Alter the shares
			for _, share := range shares {
				share.Secret.Random()
			}

			// Verify
			for _, share := range shares {
				pk := g.Base().Multiply(share.Secret)
				if secretsharing.Verify(g, share.ID, pk, share.Commitment) {
					t.Fatalf("verification succeeded but shouldn't")
				}
			}
		})
	}
}

func TestVerify_BadCommitments(t *testing.T) {
	threshold := uint16(2)
	max := uint16(3)

	for _, g := range groups {
		t.Run(g.String(), func(tt *testing.T) {
			secret := g.NewScalar().Random()

			shares, polynomial, err := secretsharing.ShardReturnPolynomial(g, secret, threshold, max)
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

func TestShard_0_Secret(t *testing.T) {
	expected := "the provided secret is zero"
	g := group.Ristretto255Sha512
	if _, err := secretsharing.Shard(g, g.NewScalar(), 3, 5); err == nil || err.Error() != expected {
		t.Fatalf("expected error %q, got %q", expected, err)
	}
}

func TestShard_0_Threshold(t *testing.T) {
	expected := "threshold is zero"
	if _, err := secretsharing.Shard(0, nil, 0, 0); err == nil || err.Error() != expected {
		t.Fatalf("expected error %q, got %q", expected, err)
	}
}

func TestShard_LowShares(t *testing.T) {
	threshold := uint16(2)
	max := threshold - 1
	expected := "number of shares must be equal or greater than the threshold"

	for _, g := range groups {
		t.Run(g.String(), func(tt *testing.T) {
			secret := g.NewScalar().Random()

			if _, err := secretsharing.Shard(g, secret, threshold, max); err == nil || err.Error() != expected {
				t.Fatalf("expected error %q, got %q", expected, err)
			}

			if _, err := secretsharing.ShardAndCommit(g, secret, threshold, max); err == nil ||
				err.Error() != expected {
				t.Fatalf("expected error %q, got %q", expected, err)
			}

			if _, _, err := secretsharing.ShardReturnPolynomial(g, secret, threshold, max); err == nil ||
				err.Error() != expected {
				t.Fatalf("expected error %q, got %q", expected, err)
			}
		})
	}
}

func testBadPolynomial(g group.Group, threshold, max uint16, p secretsharing.Polynomial, s ...*group.Scalar) error {
	var secret *group.Scalar
	if len(s) == 0 {
		secret = g.NewScalar().Random()
	} else {
		secret = s[0]
	}

	shares, polynomial, err := secretsharing.ShardReturnPolynomial(g, secret, uint16(threshold), uint16(max), p...)
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
	threshold := uint16(3)
	max := uint16(5)
	expected := "provided polynomial's first coefficient not set to the secret"

	for _, g := range groups {
		t.Run(g.String(), func(t *testing.T) {
			// Test polynomial with first coefficient not set to the secret
			polyNoSecret := secretsharing.NewPolynomial(threshold)
			polyNoSecret[0] = g.NewScalar().Random()
			polyNoSecret[1] = g.NewScalar().Random()
			polyNoSecret[2] = g.NewScalar().Random()

			t.Run(g.String(), func(tt *testing.T) {
				if err := testBadPolynomial(g, threshold, max, polyNoSecret); err == nil || err.Error() != expected {
					t.Fatalf("expected error %q, got %q", expected, err)
				}
			})
		})
	}
}

func TestBadPolynomial_NilCoeff(t *testing.T) {
	threshold := uint16(3)
	max := uint16(5)
	expected := "the polynomial has a nil coefficient"

	for _, g := range groups {
		t.Run(g.String(), func(t *testing.T) {
			// Test polynomial with a nil coefficient
			polyNilCoeff := make(secretsharing.Polynomial, threshold)
			polyNilCoeff[0] = g.NewScalar().Random()
			polyNilCoeff[1] = nil
			polyNilCoeff[2] = g.NewScalar().Random()

			t.Run(g.String(), func(tt *testing.T) {
				if err := testBadPolynomial(g, threshold, max, polyNilCoeff, polyNilCoeff[0]); err == nil ||
					err.Error() != expected {
					t.Fatalf("expected error %q, got %q", expected, err)
				}
			})
		})
	}
}

func TestBadPolynomial_ZeroCoeff(t *testing.T) {
	threshold := uint16(3)
	max := uint16(5)
	expected := "one of the polynomial's coefficients is zero"

	for _, g := range groups {
		t.Run(g.String(), func(t *testing.T) {
			// Test polynomial with a zero coefficient
			polyZeroCoeff := make(secretsharing.Polynomial, threshold)
			polyZeroCoeff[0] = g.NewScalar().Random()
			polyZeroCoeff[1] = g.NewScalar().Zero()
			polyZeroCoeff[2] = g.NewScalar().Random()

			t.Run(g.String(), func(tt *testing.T) {
				if err := testBadPolynomial(g, threshold, max, polyZeroCoeff, polyZeroCoeff[0]); err != nil &&
					err.Error() != expected {
					t.Fatalf("expected error %q, got %q", expected, err)
				}
			})
		})
	}
}

func TestBadPolynomial_WrongSize(t *testing.T) {
	threshold := uint16(2)
	max := uint16(3)
	expected := "invalid number of coefficients in polynomial"

	for _, g := range groups {
		t.Run(g.String(), func(t *testing.T) {
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
				if err := testBadPolynomial(g, threshold, max, polyShort); err != nil && err.Error() != expected {
					t.Fatalf("expected error %q, got %q", expected, err)
				}

				if err := testBadPolynomial(g, threshold, max, polyLong); err != nil && err.Error() != expected {
					t.Fatalf("expected error %q, got %q", expected, err)
				}
			})
		})
	}
}

func TestCombine_TooFewShares(t *testing.T) {
	// threshold := uint16(2)
	expected := "no shares provided"

	for _, g := range groups {
		t.Run(g.String(), func(t *testing.T) {
			// Nil shares
			if _, err := secretsharing.CombineShares(g, nil); err == nil || err.Error() != expected {
				t.Fatalf("expected error %q, got %q", expected, err)
			}

			// Zero shares
			var shares []secretsharing.Share
			if _, err := secretsharing.CombineShares(g, shares); err == nil || err.Error() != expected {
				t.Fatalf("expected error %q, got %q", expected, err)
			}
		})
	}
}

func TestCombine_BadIdentifiers_NilZero_1(t *testing.T) {
	expected := "identifier for interpolation is nil or zero"

	for _, g := range groups {
		t.Run(g.String(), func(t *testing.T) {
			badShare := []secretsharing.Share{
				&secretsharing.KeyShare{
					Secret:         nil,
					PublicKeyShare: secretsharing.PublicKeyShare{ID: 0},
				},
			}
			if _, err := secretsharing.PolynomialInterpolateConstant(g, badShare); err == nil ||
				err.Error() != expected {
				t.Fatalf("expected error %q, got %q", expected, err)
			}
		})
	}
}

func TestCombine_BadIdentifiers_Nil(t *testing.T) {
	expected := "the polynomial has a nil coefficient"

	for _, g := range groups {
		t.Run(g.String(), func(t *testing.T) {
			xCoords := secretsharing.Polynomial{g.NewScalar().SetUInt64(1), nil}
			if _, err := xCoords.DeriveInterpolatingValue(g, xCoords[0]); err == nil || err.Error() != expected {
				t.Fatalf("expected error %q, got %q", expected, err)
			}
		})
	}
}

func TestCombine_BadIdentifiers_Zero(t *testing.T) {
	expected := "one of the polynomial's coefficients is zero"

	for _, g := range groups {
		t.Run(g.String(), func(t *testing.T) {
			badShare := []secretsharing.Share{
				&secretsharing.KeyShare{
					Secret:         g.NewScalar().Random(),
					PublicKeyShare: secretsharing.PublicKeyShare{ID: 1},
				},
				&secretsharing.KeyShare{
					Secret:         g.NewScalar().Random(),
					PublicKeyShare: secretsharing.PublicKeyShare{ID: 0},
				},
			}
			if _, err := secretsharing.PolynomialInterpolateConstant(g, badShare); err == nil ||
				err.Error() != expected {
				t.Fatalf("expected error %q, got %q", expected, err)
			}
		})
	}
}

func TestCombine_BadIdentifiers_Duplicates(t *testing.T) {
	expected := "the polynomial has duplicate coefficients"

	for _, g := range groups {
		t.Run(g.String(), func(t *testing.T) {
			badShare := []secretsharing.Share{
				&secretsharing.KeyShare{
					Secret:         g.NewScalar().Random(),
					PublicKeyShare: secretsharing.PublicKeyShare{ID: 1},
				},
				&secretsharing.KeyShare{
					Secret:         g.NewScalar().Random(),
					PublicKeyShare: secretsharing.PublicKeyShare{ID: 1},
				},
			}
			if _, err := secretsharing.PolynomialInterpolateConstant(g, badShare); err == nil ||
				err.Error() != expected {
				t.Fatalf("expected error %q, got %q", expected, err)
			}
		})
	}
}

func TestPubKeyForCommitment(t *testing.T) {
	threshold := uint16(3) // threshold is the minimum amount of necessary shares to recombine the secret
	max := uint16(7)       // the max amount of key share-holders

	for _, g := range groups {
		t.Run(g.String(), func(t *testing.T) {
			// This is the global secret to be shared
			secret := g.NewScalar().Random()

			// Shard the secret into shares
			shares, err := secretsharing.ShardAndCommit(g, secret, threshold, max)
			if err != nil {
				t.Fatal(err)
			}

			publicShare := shares[0].Public()

			// No expected error
			pk, err := secretsharing.PubKeyForCommitment(g, publicShare.ID, publicShare.Commitment)
			if err != nil {
				t.Fatal(err)
			}

			if pk.Equal(publicShare.PublicKey) != 1 {
				t.Fatalf("unexpected public key:\n\twant: %v\n\tgot : %v\n", shares[0].PublicKey.Hex(), pk.Hex())
			}

			if !secretsharing.Verify(g, publicShare.ID, publicShare.PublicKey, publicShare.Commitment) {
				t.Fatal("unexpected public key")
			}
		})
	}
}

func TestPubKeyForCommitment_Bad_CommitmentNilElement(t *testing.T) {
	errCommitmentNilElement := errors.New("commitment has nil element")
	threshold := uint16(5)
	shareholders := uint16(7)

	for _, g := range groups {
		t.Run(g.String(), func(t *testing.T) {
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

			// Second element of commitment is nil and id = 1
			c := commitment[1].Copy()
			commitment[1] = nil
			if _, err = secretsharing.PubKeyForCommitment(g, shares[0].ID, commitment); err == nil ||
				err.Error() != errCommitmentNilElement.Error() {
				t.Fatalf("expected error %q, got %q", errCommitmentNilElement, err)
			}
			commitment[1] = c

			// Second element of commitment is nil
			c = commitment[1].Copy()
			commitment[1] = nil
			if _, err = secretsharing.PubKeyForCommitment(g, shares[1].ID, commitment); err == nil ||
				err.Error() != errCommitmentNilElement.Error() {
				t.Fatalf("expected error %q, got %q", errCommitmentNilElement, err)
			}
			commitment[1] = c

			// Third element of the commitment is nil
			c = commitment[2].Copy()
			commitment[2] = nil
			if _, err = secretsharing.PubKeyForCommitment(g, shares[1].ID, commitment); err == nil ||
				err.Error() != errCommitmentNilElement.Error() {
				t.Fatalf("expected error %q, got %q", errCommitmentNilElement, err)
			}
			commitment[2] = c

			// Some other element of the commitment is nil
			c = commitment[4].Copy()
			commitment[4] = nil
			if _, err = secretsharing.PubKeyForCommitment(g, shares[1].ID, commitment); err == nil ||
				err.Error() != errCommitmentNilElement.Error() {
				t.Fatalf("expected error %q, got %q", errCommitmentNilElement, err)
			}
		})
	}
}

func comparePublicKeyShare(s1, s2 *secretsharing.PublicKeyShare) error {
	if s1.PublicKey.Equal(s2.PublicKey) != 1 {
		return fmt.Errorf("Expected equality on PublicKey:\n\t%s\n\t%s\n", s1.PublicKey.Hex(), s2.PublicKey.Hex())
	}

	if s1.ID != s2.ID {
		return fmt.Errorf("Expected equality on ID:\n\t%d\n\t%d\n", s1.ID, s2.ID)
	}

	if s1.Group != s2.Group {
		return fmt.Errorf("Expected equality on Group:\n\t%v\n\t%v\n", s1.Group, s2.Group)
	}

	if len(s1.Commitment) != len(s2.Commitment) {
		return fmt.Errorf(
			"Expected equality on Commitment length:\n\t%d\n\t%d\n",
			len(s1.Commitment),
			len(s2.Commitment),
		)
	}

	for i := range s1.Commitment {
		if s1.Commitment[i].Equal(s2.Commitment[i]) != 1 {
			return fmt.Errorf(
				"Expected equality on Commitment %d:\n\t%s\n\t%s\n",
				i,
				s1.Commitment[i].Hex(),
				s2.Commitment[i].Hex(),
			)
		}
	}

	return nil
}

func compareKeyShares(s1, s2 *secretsharing.KeyShare) error {
	if s1.Secret.Equal(s2.Secret) != 1 {
		return fmt.Errorf("Expected equality on Secret:\n\t%s\n\t%s\n", s1.Secret.Hex(), s2.Secret.Hex())
	}

	if s1.GroupPublicKey.Equal(s2.GroupPublicKey) != 1 {
		return fmt.Errorf(
			"Expected equality on GroupPublicKey:\n\t%s\n\t%s\n",
			s1.GroupPublicKey.Hex(),
			s2.GroupPublicKey.Hex(),
		)
	}

	return comparePublicKeyShare(&s1.PublicKeyShare, &s2.PublicKeyShare)
}

func TestEncoding_Bytes(t *testing.T) {
	threshold := uint16(3) // threshold is the minimum amount of necessary shares to recombine the secret
	max := uint16(7)       // the max amount of key share-holders

	for _, g := range groups {
		t.Run(g.String(), func(t *testing.T) {
			// This is the global secret to be shared
			secret := g.NewScalar().Random()

			// Shard the secret into shares
			shares, err := secretsharing.ShardAndCommit(g, secret, threshold, max)
			if err != nil {
				t.Fatal(err)
			}

			// PublicKeyShare
			b := shares[0].Public().Encode()

			decodedPKS := &secretsharing.PublicKeyShare{}
			if err = decodedPKS.Decode(b); err != nil {
				t.Fatal(err)
			}

			if err = comparePublicKeyShare(&shares[0].PublicKeyShare, decodedPKS); err != nil {
				t.Fatal(err)
			}

			// KeyShare
			b = shares[0].Encode()

			decodedKS := &secretsharing.KeyShare{}
			if err = decodedKS.Decode(b); err != nil {
				t.Fatal(err)
			}

			if err = compareKeyShares(shares[0], decodedKS); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestEncoding_Hex(t *testing.T) {
	threshold := uint16(3) // threshold is the minimum amount of necessary shares to recombine the secret
	max := uint16(7)       // the max amount of key share-holders

	for _, g := range groups {
		t.Run(g.String(), func(t *testing.T) {
			// This is the global secret to be shared
			secret := g.NewScalar().Random()

			// Shard the secret into shares
			shares, err := secretsharing.ShardAndCommit(g, secret, threshold, max)
			if err != nil {
				t.Fatal(err)
			}

			// PublicKeyShare
			h := shares[0].Public().Hex()

			decodedPKS := new(secretsharing.PublicKeyShare)
			if err = decodedPKS.DecodeHex(h); err != nil {
				t.Fatal(err)
			}

			if err = comparePublicKeyShare(&shares[0].PublicKeyShare, decodedPKS); err != nil {
				t.Fatal(err)
			}

			// KeyShare
			h = shares[0].Hex()

			decodedKS := &secretsharing.KeyShare{}
			if err = decodedKS.DecodeHex(h); err != nil {
				t.Fatal(err)
			}

			if err = compareKeyShares(shares[0], decodedKS); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestEncoding_JSON(t *testing.T) {
	threshold := uint16(3) // threshold is the minimum amount of necessary shares to recombine the secret
	max := uint16(7)       // the max amount of key share-holders

	for _, g := range groups {
		t.Run(g.String(), func(t *testing.T) {
			// This is the global secret to be shared
			secret := g.NewScalar().Random()

			// Shard the secret into shares
			shares, err := secretsharing.ShardAndCommit(g, secret, threshold, max)
			if err != nil {
				t.Fatal(err)
			}

			// PublicKeyShare
			j, err := json.Marshal(shares[0].PublicKeyShare)
			if err != nil {
				t.Fatal(err)
			}

			decodedPKS := &secretsharing.PublicKeyShare{}
			if err = json.Unmarshal(j, decodedPKS); err != nil {
				t.Fatal(err)
			}

			if err = comparePublicKeyShare(&shares[0].PublicKeyShare, decodedPKS); err != nil {
				t.Fatal(err)
			}

			// KeyShare
			j, err = json.Marshal(shares[0])
			if err != nil {
				t.Fatal(err)
			}

			decodedKS := &secretsharing.KeyShare{}
			if err = json.Unmarshal(j, decodedKS); err != nil {
				t.Fatal(err)
			}

			if err = compareKeyShares(shares[0], decodedKS); err != nil {
				t.Fatal(err)
			}
		})
	}
}

type serde interface {
	Decode([]byte) error
	DecodeHex(h string) error
	UnmarshalJSON(data []byte) error
}

func testDecodeError(t *testing.T, encoded []byte, s serde, expectedError error) {
	if err := s.Decode(encoded); err == nil || err.Error() != expectedError.Error() {
		t.Fatalf("expected error %q, got %q", expectedError, err)
	}
}

func testDecodeErrorPrefix(t *testing.T, s serde, data []byte, expectedPrefix error) {
	if err := s.Decode(data); err == nil ||
		!strings.HasPrefix(err.Error(), expectedPrefix.Error()) {
		t.Fatalf("expected error %q, got %q", expectedPrefix, err)
	}
}

func testDecodeHexError(t *testing.T, s serde, data string, expectedError error) {
	if err := s.DecodeHex(data); err == nil || err.Error() != expectedError.Error() {
		t.Fatalf("expected error %q, got %q", expectedError, err)
	}
}

func testUnmarshalJSONError(t *testing.T, s serde, data []byte, expectedError error) {
	if err := json.Unmarshal(data, s); err == nil || err.Error() != expectedError.Error() {
		t.Fatalf("expected error %q, got %q", expectedError, err)
	}
}

func testUnmarshalJSONErrorPrefix(t *testing.T, s serde, data []byte, expectedPrefix error) {
	if err := json.Unmarshal(data, s); err == nil ||
		!strings.HasPrefix(err.Error(), expectedPrefix.Error()) {
		t.Fatalf("expected error %q, got %q", expectedPrefix, err)
	}
}

func replaceStringInBytes(data []byte, old, new string) []byte {
	s := string(data)
	s = strings.Replace(s, old, new, 1)

	return []byte(s)
}

func getBadNistElement(t *testing.T, g group.Group) []byte {
	element := make([]byte, g.ElementLength())
	if _, err := rand.Read(element); err != nil {
		// We can as well not panic and try again in a loop and a counter to stop.
		panic(fmt.Errorf("unexpected error in generating random bytes : %w", err))
	}
	// detag compression
	element[0] = 4

	// test if invalid compression is detected
	err := g.NewElement().Decode(element)
	if err == nil {
		t.Errorf("detagged compressed point did not yield an error for group %s", g)
	}

	return element
}

func getBadRistrettoElement() []byte {
	a := "2a292df7e32cababbd9de088d1d1abec9fc0440f637ed2fba145094dc14bea08"
	decoded, _ := hex.DecodeString(a)

	return decoded
}

func getBadElement(t *testing.T, g group.Group) []byte {
	switch g {
	case group.Ristretto255Sha512:
		return getBadRistrettoElement()
	default:
		return getBadNistElement(t, g)
	}
}

func getBadScalar(g group.Group) []byte {
	order := g.Order()
	o, _ := new(big.Int).SetString(order, 0)
	o.Add(o, new(big.Int).SetInt64(10))
	out := make([]byte, g.ScalarLength())
	o.FillBytes(out)
	if g == group.Ristretto255Sha512 || g == group.Edwards25519Sha512 {
		slices.Reverse(out)
	}

	return out
}

func TestEncoding_PublicKeyShare_Bad(t *testing.T) {
	threshold := uint16(3)
	max := uint16(4)

	errEncodingInvalidLength := errors.New("failed to decode PublicKeyShare: invalid encoding length")
	errEncodingInvalidGroup := errors.New("failed to decode PublicKeyShare: invalid group identifier")
	errEncodingInvalidJSONEncoding := errors.New("failed to decode PublicKeyShare: invalid JSON encoding")

	for _, g := range groups {
		t.Run(g.String(), func(t *testing.T) {
			secret := g.NewScalar().Random()
			shares, err := secretsharing.ShardAndCommit(g, secret, threshold, max)
			if err != nil {
				t.Fatal(err)
			}

			badElement := getBadElement(t, g)

			// Decode: empty
			testDecodeError(t, nil, new(secretsharing.PublicKeyShare), errEncodingInvalidLength)

			// Decode: bad group
			encoded := shares[0].Public().Encode()
			encoded[0] = 0
			testDecodeError(t, encoded, new(secretsharing.PublicKeyShare), errEncodingInvalidGroup)

			encoded[0] = 255
			testDecodeError(t, encoded, new(secretsharing.PublicKeyShare), errEncodingInvalidGroup)

			// Decode: header too short
			encoded = shares[0].Public().Encode()
			testDecodeError(t, encoded[:6], new(secretsharing.PublicKeyShare), errEncodingInvalidLength)

			// Decode: Bad Length
			testDecodeError(t, encoded[:19], new(secretsharing.PublicKeyShare), errEncodingInvalidLength)

			// Decode: Bad public key
			encoded = slices.Replace(encoded, 7, 7+g.ElementLength(), badElement...)
			expectedErrorPrefix := errors.New("failed to decode PublicKeyShare: failed to decode public key")
			testDecodeErrorPrefix(t, new(secretsharing.PublicKeyShare), encoded, expectedErrorPrefix)

			// Decode: bad commitment
			encoded = shares[0].Public().Encode()
			offset := 7 + 2*g.ElementLength()
			encoded = slices.Replace(encoded, offset, offset+g.ElementLength(), badElement...)
			expectedErrorPrefix = errors.New("failed to decode PublicKeyShare: failed to decode commitment 2")
			testDecodeErrorPrefix(t, new(secretsharing.PublicKeyShare), encoded, expectedErrorPrefix)

			// UnmarshallJSON: bad json
			data, err := json.Marshal(shares[0])
			if err != nil {
				t.Fatal(err)
			}

			data = replaceStringInBytes(data, "\"group\"", "bad")
			expectedErrorPrefix = errors.New("invalid character 'b' looking for beginning of object key string")
			testUnmarshalJSONErrorPrefix(t, new(secretsharing.PublicKeyShare), data, expectedErrorPrefix)

			// UnmarshallJSON: bad group, no group
			data, err = json.Marshal(shares[0])
			if err != nil {
				t.Fatal(err)
			}

			data = replaceStringInBytes(data, "\"group\"", "\"nope\"")
			testUnmarshalJSONError(t, new(secretsharing.PublicKeyShare), data, errEncodingInvalidJSONEncoding)

			// UnmarshallJSON: bad group
			data, err = json.Marshal(shares[0])
			if err != nil {
				t.Fatal(err)
			}

			data = replaceStringInBytes(data, fmt.Sprintf("\"group\":%d", g), "\"group\":70")
			testUnmarshalJSONError(t, new(secretsharing.PublicKeyShare), data, errEncodingInvalidGroup)

			// UnmarshallJSON: bad group
			data, err = json.Marshal(shares[0])
			if err != nil {
				t.Fatal(err)
			}

			data = replaceStringInBytes(data, fmt.Sprintf("\"group\":%d", g), "\"group\":17")
			testUnmarshalJSONError(t, new(secretsharing.PublicKeyShare), data, errEncodingInvalidGroup)

			// UnmarshallJSON: bad ciphersuite
			data, err = json.Marshal(shares[0])
			if err != nil {
				t.Fatal(err)
			}

			overflow := "9223372036854775808" // MaxInt64 + 1
			data = replaceStringInBytes(data, fmt.Sprintf("\"group\":%d", g), "\"group\":"+overflow)

			expectedErrorPrefix = errors.New(
				"failed to decode PublicKeyShare: failed to read Group: strconv.Atoi: parsing \"9223372036854775808\": value out of range",
			)

			testUnmarshalJSONErrorPrefix(t, new(secretsharing.PublicKeyShare), data, expectedErrorPrefix)

			// UnmarshallJSON: no error on empty commitment
			data, err = json.Marshal(shares[0])
			if err != nil {
				t.Fatal(err)
			}

			data = replaceStringInBytes(data, "\"commitment\"", "\"nope\"")

			if err = json.Unmarshal(data, new(secretsharing.PublicKeyShare)); err != nil {
				t.Fatalf("unexpected error %q", err)
			}

			// UnmarshallJSON: no error on empty commitment
			data, err = json.Marshal(shares[0])
			if err != nil {
				t.Fatal(err)
			}

			data = replaceStringInBytes(data, "\"commitment\"", "\"commitment\":[],\"other\"")
			if err = json.Unmarshal(data, new(secretsharing.PublicKeyShare)); err != nil {
				t.Fatalf("unexpected error %q", err)
			}

			// UnmarshallJSON: no error on empty commitment
			shares[0].Commitment = []*group.Element{}
			data, err = json.Marshal(shares[0])
			if err != nil {
				t.Fatal(err)
			}

			data = replaceStringInBytes(data, "\"commitment\"", "\"nope\"")

			if err = json.Unmarshal(data, new(secretsharing.PublicKeyShare)); err != nil {
				t.Fatalf("unexpected error %q", err)
			}

			// UnmarshallJSON: excessive commitment length
			shares[0].Commitment = make([]*group.Element, 65536)
			for i := range 65536 {
				shares[0].Commitment[i] = g.NewElement()
			}

			data, err = json.Marshal(shares[0])
			if err != nil {
				t.Fatal(err)
			}

			errInvalidPolynomialLength := errors.New("failed to decode PublicKeyShare: invalid polynomial length (exceeds uint16 limit 65535)")
			testUnmarshalJSONError(t, new(secretsharing.PublicKeyShare), data, errInvalidPolynomialLength)
		})
	}
}

func TestEncoding_KeyShare_Bad(t *testing.T) {
	threshold := uint16(1)
	max := uint16(2)

	errEncodingInvalidLength := errors.New("failed to decode KeyShare: invalid encoding length")
	errEncodingInvalidGroup := errors.New("failed to decode KeyShare: invalid group identifier")
	errEncodingInvalidJSONEncoding := errors.New("failed to decode KeyShare: invalid JSON encoding")

	for _, g := range groups {
		t.Run(g.String(), func(t *testing.T) {
			secret := g.NewScalar().Random()
			shares, err := secretsharing.ShardAndCommit(g, secret, threshold, max)
			if err != nil {
				t.Fatal(err)
			}

			badScalar := getBadScalar(g)
			badElement := getBadElement(t, g)

			// Decode: empty
			testDecodeError(t, nil, new(secretsharing.KeyShare), errEncodingInvalidLength)

			// Decode: bad group
			encoded := shares[0].Encode()
			encoded[0] = 0
			testDecodeError(t, encoded, new(secretsharing.KeyShare), errEncodingInvalidGroup)

			encoded[0] = 255
			testDecodeError(t, encoded, new(secretsharing.KeyShare), errEncodingInvalidGroup)

			// Decode: header too short
			encoded = shares[0].Encode()
			testDecodeError(t, encoded[:12], new(secretsharing.KeyShare), errEncodingInvalidLength)

			// Decode: Bad Length
			testDecodeError(t, encoded[:25], new(secretsharing.KeyShare), errEncodingInvalidLength)

			// Decode: Bad public key share
			offset := 7
			encoded = shares[0].Encode()
			encoded = slices.Replace(encoded, offset, offset+g.ElementLength(), badElement...)

			expectedErrorPrefix := errors.New("failed to decode KeyShare: failed to decode PublicKeyShare: failed to decode public key: element Decode: ")
			testDecodeErrorPrefix(t, new(secretsharing.KeyShare), encoded, expectedErrorPrefix)

			// Decode: Bad scalar
			offset += g.ElementLength() + len(shares[0].Commitment)*g.ElementLength()
			encoded = shares[0].Encode()
			encoded = slices.Replace(encoded, offset, offset+g.ScalarLength(), badScalar...)
			expectedErrorPrefix = errors.New("failed to decode KeyShare: failed to decode secret key: scalar Decode: ")

			testDecodeErrorPrefix(t, new(secretsharing.KeyShare), encoded, expectedErrorPrefix)

			// Decode: bad group public key
			offset += g.ScalarLength()
			encoded = shares[0].Encode()
			encoded = slices.Replace(encoded, offset, offset+g.ElementLength(), badElement...)
			expectedErrorPrefix = errors.New("failed to decode KeyShare: failed to decode GroupPublicKey: element Decode: ")

			testDecodeErrorPrefix(t, new(secretsharing.KeyShare), encoded, expectedErrorPrefix)

			// Bad Hex
			h := shares[0].Hex()
			expectedErrorPrefix = errors.New("failed to decode KeyShare: encoding/hex: odd length hex string")
			testDecodeHexError(t, new(secretsharing.KeyShare), h[:len(h)-1], expectedErrorPrefix)

			// UnmarshallJSON: bad json
			data, err := json.Marshal(shares[0])
			if err != nil {
				t.Fatal(err)
			}

			data = replaceStringInBytes(data, "\"group\"", "bad")
			expectedErrorPrefix = errors.New("invalid character 'b' looking for beginning of object key string")
			testUnmarshalJSONErrorPrefix(t, new(secretsharing.KeyShare), data, expectedErrorPrefix)

			// UnmarshallJSON: bad group encoding
			data, err = json.Marshal(shares[0])
			if err != nil {
				t.Fatal(err)
			}

			data = replaceStringInBytes(data, fmt.Sprintf("\"group\":%d", g), "\"group\":-1")
			testUnmarshalJSONError(t, new(secretsharing.KeyShare), data, errEncodingInvalidJSONEncoding)
		})
	}
}
