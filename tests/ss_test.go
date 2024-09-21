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
	maxParticipants := uint16(5)

	for _, g := range groups {
		t.Run(g.String(), func(t *testing.T) {
			secret := g.NewScalar().Random()

			shares, err := secretsharing.Shard(g, secret, threshold, maxParticipants)
			if err != nil {
				t.Fatal(err)
			}

			if len(shares) != int(maxParticipants) {
				t.Fatalf("expected %d shares, got %d", maxParticipants, len(shares))
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
			if err, _ = testCombine(g, secret, shares[:maxParticipants]); err != nil {
				t.Fatalf("unexpected error: %s", err)
			}
		})
	}
}

func TestNewPolynomial_Ints(t *testing.T) {
	maxParticipants := uint16(3)

	for _, g := range groups {
		t.Run(g.String(), func(tt *testing.T) {
			pRef := secretsharing.NewPolynomial(maxParticipants)
			ints := make([]uint16, maxParticipants)
			shares := make([]*secretsharing.KeyShare, maxParticipants)
			for i := range maxParticipants {
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

			for i := range maxParticipants {
				if pRef[i].Equal(pInts[i]) != 1 || pRef[i].Equal(pShares[i]) != 1 {
					t.Fatal("expected equality")
				}
			}
		})
	}
}

func TestSecretSharing_WithPolynomial(t *testing.T) {
	threshold := uint16(2)
	maxParticipants := uint16(3)

	for _, g := range groups {
		t.Run(g.String(), func(tt *testing.T) {
			secret := g.NewScalar().Random()
			polynomial := make(secretsharing.Polynomial, threshold)
			polynomial[0] = secret
			polynomial[1] = g.NewScalar().Random()

			// Provide the all elements of the polynomial with the prepending secret
			if _, err := secretsharing.Shard(g, secret, threshold, maxParticipants, polynomial...); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestCommitment(t *testing.T) {
	threshold := uint16(3)
	maxParticipants := uint16(5)

	for _, g := range groups {
		t.Run(g.String(), func(tt *testing.T) {
			secret := g.NewScalar().Random()

			shares, err := secretsharing.ShardAndCommit(g, secret, threshold, maxParticipants)
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

				if !secretsharing.Verify(g, pubkey.ID, pk, pubkey.VssCommitment) {
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
	maxParticipants := uint16(3)

	for _, g := range groups {
		t.Run(g.String(), func(tt *testing.T) {
			secret := g.NewScalar().Random()

			shares, err := secretsharing.ShardAndCommit(g, secret, threshold, maxParticipants)
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
				if secretsharing.Verify(g, share.ID, pk, share.VssCommitment) {
					t.Fatalf("verification succeeded but shouldn't")
				}
			}
		})
	}
}

func TestVerify_BadCommitments(t *testing.T) {
	threshold := uint16(2)
	maxParticipants := uint16(3)

	for _, g := range groups {
		t.Run(g.String(), func(tt *testing.T) {
			secret := g.NewScalar().Random()

			shares, polynomial, err := secretsharing.ShardReturnPolynomial(g, secret, threshold, maxParticipants)
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

			if secretsharing.Verify(g, 0, nil, make(secretsharing.VssCommitment, 0)) {
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
	maxParticipants := threshold - 1
	expected := "number of shares must be equal or greater than the threshold"

	for _, g := range groups {
		t.Run(g.String(), func(tt *testing.T) {
			secret := g.NewScalar().Random()

			if _, err := secretsharing.Shard(g, secret, threshold, maxParticipants); err == nil ||
				err.Error() != expected {
				t.Fatalf("expected error %q, got %q", expected, err)
			}

			if _, err := secretsharing.ShardAndCommit(g, secret, threshold, maxParticipants); err == nil ||
				err.Error() != expected {
				t.Fatalf("expected error %q, got %q", expected, err)
			}

			if _, _, err := secretsharing.ShardReturnPolynomial(g, secret, threshold, maxParticipants); err == nil ||
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
	maxParticipants := uint16(5)
	expected := "provided polynomial's first coefficient not set to the secret"

	for _, g := range groups {
		t.Run(g.String(), func(t *testing.T) {
			// Test polynomial with first coefficient not set to the secret
			polyNoSecret := secretsharing.NewPolynomial(threshold)
			polyNoSecret[0] = g.NewScalar().Random()
			polyNoSecret[1] = g.NewScalar().Random()
			polyNoSecret[2] = g.NewScalar().Random()

			t.Run(g.String(), func(tt *testing.T) {
				if err := testBadPolynomial(g, threshold, maxParticipants, polyNoSecret); err == nil ||
					err.Error() != expected {
					t.Fatalf("expected error %q, got %q", expected, err)
				}
			})
		})
	}
}

func TestBadPolynomial_NilCoeff(t *testing.T) {
	threshold := uint16(3)
	maxParticipants := uint16(5)
	expected := "the polynomial has a nil coefficient"

	for _, g := range groups {
		t.Run(g.String(), func(t *testing.T) {
			// Test polynomial with a nil coefficient
			polyNilCoeff := make(secretsharing.Polynomial, threshold)
			polyNilCoeff[0] = g.NewScalar().Random()
			polyNilCoeff[1] = nil
			polyNilCoeff[2] = g.NewScalar().Random()

			t.Run(g.String(), func(tt *testing.T) {
				if err := testBadPolynomial(g, threshold, maxParticipants, polyNilCoeff, polyNilCoeff[0]); err == nil ||
					err.Error() != expected {
					t.Fatalf("expected error %q, got %q", expected, err)
				}
			})
		})
	}
}

func TestBadPolynomial_ZeroCoeff(t *testing.T) {
	threshold := uint16(3)
	maxParticipants := uint16(5)
	expected := "one of the polynomial's coefficients is zero"

	for _, g := range groups {
		t.Run(g.String(), func(t *testing.T) {
			// Test polynomial with a zero coefficient
			polyZeroCoeff := make(secretsharing.Polynomial, threshold)
			polyZeroCoeff[0] = g.NewScalar().Random()
			polyZeroCoeff[1] = g.NewScalar().Zero()
			polyZeroCoeff[2] = g.NewScalar().Random()

			t.Run(g.String(), func(tt *testing.T) {
				if err := testBadPolynomial(g, threshold, maxParticipants, polyZeroCoeff, polyZeroCoeff[0]); err != nil &&
					err.Error() != expected {
					t.Fatalf("expected error %q, got %q", expected, err)
				}
			})
		})
	}
}

func TestBadPolynomial_WrongSize(t *testing.T) {
	threshold := uint16(2)
	maxParticipants := uint16(3)
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
				if err := testBadPolynomial(g, threshold, maxParticipants, polyShort); err != nil &&
					err.Error() != expected {
					t.Fatalf("expected error %q, got %q", expected, err)
				}

				if err := testBadPolynomial(g, threshold, maxParticipants, polyLong); err != nil &&
					err.Error() != expected {
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
	threshold := uint16(3)       // threshold is the minimum amount of necessary shares to recombine the secret
	maxParticipants := uint16(7) // the max amount of key share-holders

	for _, g := range groups {
		t.Run(g.String(), func(t *testing.T) {
			// This is the global secret to be shared
			secret := g.NewScalar().Random()

			// Shard the secret into shares
			shares, err := secretsharing.ShardAndCommit(g, secret, threshold, maxParticipants)
			if err != nil {
				t.Fatal(err)
			}

			publicShare := shares[0].Public()

			// No expected error
			pk, err := secretsharing.PubKeyForCommitment(g, publicShare.ID, publicShare.VssCommitment)
			if err != nil {
				t.Fatal(err)
			}

			if pk.Equal(publicShare.PublicKey) != 1 {
				t.Fatalf("unexpected public key:\n\twant: %v\n\tgot : %v\n", shares[0].PublicKey.Hex(), pk.Hex())
			}

			if !secretsharing.Verify(g, publicShare.ID, publicShare.PublicKey, publicShare.VssCommitment) {
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

	if len(s1.VssCommitment) != len(s2.VssCommitment) {
		return fmt.Errorf(
			"Expected equality on VssCommitment length:\n\t%d\n\t%d\n",
			len(s1.VssCommitment),
			len(s2.VssCommitment),
		)
	}

	for i := range s1.VssCommitment {
		if s1.VssCommitment[i].Equal(s2.VssCommitment[i]) != 1 {
			return fmt.Errorf(
				"Expected equality on VssCommitment %d:\n\t%s\n\t%s\n",
				i,
				s1.VssCommitment[i].Hex(),
				s2.VssCommitment[i].Hex(),
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
	threshold := uint16(3)       // threshold is the minimum amount of necessary shares to recombine the secret
	maxParticipants := uint16(7) // the maxParticipants amount of key share-holders

	for _, g := range groups {
		t.Run(g.String(), func(t *testing.T) {
			// This is the global secret to be shared
			secret := g.NewScalar().Random()

			// Shard the secret into shares
			shares, err := secretsharing.ShardAndCommit(g, secret, threshold, maxParticipants)
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

			// Registry
			registry := makeRegistry(t, g, threshold, maxParticipants, shares)
			b = registry.Encode()

			decodedRegistry := new(secretsharing.PublicKeyShareRegistry)
			if err = decodedRegistry.Decode(b); err != nil {
				t.Fatal(err)
			}

			if err = compareRegistries(registry, decodedRegistry); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestEncoding_Hex(t *testing.T) {
	threshold := uint16(3)       // threshold is the minimum amount of necessary shares to recombine the secret
	maxParticipants := uint16(7) // the maxParticipants amount of key share-holders

	for _, g := range groups {
		t.Run(g.String(), func(t *testing.T) {
			// This is the global secret to be shared
			secret := g.NewScalar().Random()

			// Shard the secret into shares
			shares, err := secretsharing.ShardAndCommit(g, secret, threshold, maxParticipants)
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

			// Registry
			registry := makeRegistry(t, g, threshold, maxParticipants, shares)
			h = registry.Hex()

			decodedRegistry := new(secretsharing.PublicKeyShareRegistry)
			if err = decodedRegistry.DecodeHex(h); err != nil {
				t.Fatal(err)
			}

			if err = compareRegistries(registry, decodedRegistry); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestEncoding_JSON(t *testing.T) {
	threshold := uint16(3)       // threshold is the minimum amount of necessary shares to recombine the secret
	maxParticipants := uint16(7) // the maxParticipants amount of key share-holders

	for _, g := range groups {
		t.Run(g.String(), func(t *testing.T) {
			// This is the global secret to be shared
			secret := g.NewScalar().Random()

			// Shard the secret into shares
			shares, err := secretsharing.ShardAndCommit(g, secret, threshold, maxParticipants)
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

			// Registry
			registry := makeRegistry(t, g, threshold, maxParticipants, shares)
			j, err = json.Marshal(registry)
			if err != nil {
				t.Fatal(err)
			}

			decodedRegistry := new(secretsharing.PublicKeyShareRegistry)
			if err = json.Unmarshal(j, decodedRegistry); err != nil {
				t.Fatal(err)
			}

			if err = compareRegistries(registry, decodedRegistry); err != nil {
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
	err := json.Unmarshal(data, s)
	if err == nil ||
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
	maxParticipants := uint16(4)

	errEncodingInvalidLength := errors.New("failed to decode PublicKeyShare: invalid encoding length")
	errEncodingInvalidGroup := errors.New("failed to decode PublicKeyShare: invalid group identifier")
	errEncodingInvalidJSONEncoding := errors.New("failed to decode PublicKeyShare: invalid JSON encoding")

	for _, g := range groups {
		t.Run(g.String(), func(t *testing.T) {
			secret := g.NewScalar().Random()
			shares, err := secretsharing.ShardAndCommit(g, secret, threshold, maxParticipants)
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

			// Bad Hex
			h := shares[0].Public().Hex()
			expectedErrorPrefix = errors.New("failed to decode PublicKeyShare: encoding/hex: odd length hex string")
			testDecodeHexError(t, new(secretsharing.PublicKeyShare), h[:len(h)-1], expectedErrorPrefix)

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

			data = replaceStringInBytes(data, "\"vssCommitment\"", "\"nope\"")

			if err = json.Unmarshal(data, new(secretsharing.PublicKeyShare)); err != nil {
				t.Fatalf("unexpected error %q", err)
			}

			// UnmarshallJSON: no error on empty commitment
			data, err = json.Marshal(shares[0])
			if err != nil {
				t.Fatal(err)
			}

			data = replaceStringInBytes(data, "\"vssCommitment\"", "\"vssCommitment\":[],\"other\"")
			if err = json.Unmarshal(data, new(secretsharing.PublicKeyShare)); err != nil {
				t.Fatalf("unexpected error %q", err)
			}

			// UnmarshallJSON: no error on empty commitment
			shares[0].VssCommitment = []*group.Element{}
			data, err = json.Marshal(shares[0])
			if err != nil {
				t.Fatal(err)
			}

			data = replaceStringInBytes(data, "\"vssCommitment\"", "\"nope\"")

			if err = json.Unmarshal(data, new(secretsharing.PublicKeyShare)); err != nil {
				t.Fatalf("unexpected error %q", err)
			}

			// UnmarshallJSON: excessive commitment length
			shares[0].VssCommitment = make([]*group.Element, 65536)
			for i := range 65536 {
				shares[0].VssCommitment[i] = g.NewElement()
			}

			data, err = json.Marshal(shares[0])
			if err != nil {
				t.Fatal(err)
			}

			errInvalidPolynomialLength := errors.New(
				"failed to decode PublicKeyShare: invalid polynomial length (exceeds uint16 limit 65535)",
			)
			testUnmarshalJSONError(t, new(secretsharing.PublicKeyShare), data, errInvalidPolynomialLength)
		})
	}
}

func TestEncoding_KeyShare_Bad(t *testing.T) {
	threshold := uint16(1)
	maxParticipants := uint16(2)

	errEncodingInvalidLength := errors.New("failed to decode KeyShare: invalid encoding length")
	errEncodingInvalidGroup := errors.New("failed to decode KeyShare: invalid group identifier")
	errEncodingInvalidJSONEncoding := errors.New("failed to decode KeyShare: invalid JSON encoding")

	for _, g := range groups {
		t.Run(g.String(), func(t *testing.T) {
			secret := g.NewScalar().Random()
			shares, err := secretsharing.ShardAndCommit(g, secret, threshold, maxParticipants)
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

			expectedErrorPrefix := errors.New(
				"failed to decode KeyShare: failed to decode PublicKeyShare: failed to decode public key: element Decode: ",
			)
			testDecodeErrorPrefix(t, new(secretsharing.KeyShare), encoded, expectedErrorPrefix)

			// Decode: Bad scalar
			offset += g.ElementLength() + len(shares[0].VssCommitment)*g.ElementLength()
			encoded = shares[0].Encode()
			encoded = slices.Replace(encoded, offset, offset+g.ScalarLength(), badScalar...)
			expectedErrorPrefix = errors.New("failed to decode KeyShare: failed to decode secret key: scalar Decode: ")

			testDecodeErrorPrefix(t, new(secretsharing.KeyShare), encoded, expectedErrorPrefix)

			// Decode: bad group public key
			offset += g.ScalarLength()
			encoded = shares[0].Encode()
			encoded = slices.Replace(encoded, offset, offset+g.ElementLength(), badElement...)
			expectedErrorPrefix = errors.New(
				"failed to decode KeyShare: failed to decode GroupPublicKey: element Decode: ",
			)

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

func TestRegistry_Add_Bad(t *testing.T) {
	errPublicKeyShareRegistered := errors.New("the public key share is already registered")
	errPublicKeyShareCapacityExceeded := errors.New("can't add another public key share (full capacity)")

	for _, g := range groups {
		t.Run(g.String(), func(t *testing.T) {
			// Shard the secret into shares
			shares, err := secretsharing.ShardAndCommit(g, nil, 3, 5)
			if err != nil {
				t.Fatal(err)
			}

			registry := makeRegistry(t, g, 3, 5, shares)

			// add a public key share that has already been added
			if err := registry.Add(shares[0].Public()); err == nil ||
				err.Error() != errPublicKeyShareRegistered.Error() {
				t.Fatalf("expected error %q, got %q", errPublicKeyShareRegistered, err)
			}

			// add a share though we're full
			shares[0].ID = 5 + 1
			if err := registry.Add(shares[0].Public()); err == nil ||
				err.Error() != errPublicKeyShareCapacityExceeded.Error() {
				t.Fatalf("expected error %q, got %q", errPublicKeyShareCapacityExceeded, err)
			}
		})
	}
}

func TestRegistry_Get(t *testing.T) {
	for _, g := range groups {
		t.Run(g.String(), func(t *testing.T) {
			// Shard the secret into shares
			shares, err := secretsharing.ShardAndCommit(g, nil, 3, 5)
			if err != nil {
				t.Fatal(err)
			}

			registry := makeRegistry(t, g, 3, 5, shares)

			id := 5 - 1
			if registry.Get(uint16(id)) == nil {
				t.Fatal("Get returned nil")
			}

			id = 5 + 1
			if registry.Get(uint16(id)) != nil {
				t.Fatalf("Get returned non-nil: %d", id)
			}
		})
	}
}

func TestRegistry_VerifyPublicKey(t *testing.T) {
	errNilPubKey := errors.New("the provided public key is nil")
	errRegistryHasNilPublicKey := errors.New("encountered a nil public key in registry")
	errVerifyBadPubKey := errors.New("the public key differs from the one registered")
	errVerifyUnknownID := errors.New("the requested identifier is not registered")
	for _, g := range groups {
		t.Run(g.String(), func(t *testing.T) {
			// Shard the secret into shares
			shares, err := secretsharing.ShardAndCommit(g, nil, 3, 5)
			if err != nil {
				t.Fatal(err)
			}

			registry := makeRegistry(t, g, 3, 5, shares)

			id := uint16(1)
			pk := registry.PublicKeyShares[id].PublicKey

			if err := registry.VerifyPublicKey(id, pk); err != nil {
				t.Fatalf("unexpected error %q", err)
			}

			if err := registry.VerifyPublicKey(id, nil); err == nil || err.Error() != errNilPubKey.Error() {
				t.Fatalf("expecter error %q, got %q", errNilPubKey, err)
			}

			expected := fmt.Errorf("%w for ID %d", errVerifyBadPubKey, id)
			if err := registry.VerifyPublicKey(id, g.NewElement()); err == nil || err.Error() != expected.Error() {
				t.Fatalf("expecter error %q, got %q", expected, err)
			}

			registry.PublicKeyShares[1].PublicKey = nil
			expected = fmt.Errorf("%w for ID %d", errRegistryHasNilPublicKey, id)
			if err := registry.VerifyPublicKey(id, g.NewElement()); err == nil || err.Error() != expected.Error() {
				t.Fatalf("expecter error %q, got %q", expected, err)
			}

			expected = fmt.Errorf("%w: %q", errVerifyUnknownID, 0)
			if err := registry.VerifyPublicKey(0, g.NewElement()); err == nil || err.Error() != expected.Error() {
				t.Fatalf("expecter error %q, got %q", expected, err)
			}
		})
	}
}

func compareRegistries(r1, r2 *secretsharing.PublicKeyShareRegistry) error {
	if r1.Group != r2.Group || r1.Total != r2.Total || r1.Threshold != r2.Threshold {
		return errors.New("wrong header")
	}

	if r1.GroupPublicKey.Equal(r2.GroupPublicKey) != 1 {
		return errors.New("wrong gpk")
	}

	if len(r1.PublicKeyShares) != len(r2.PublicKeyShares) {
		return errors.New("wrong pks length")
	}

	for i, pks := range r1.PublicKeyShares {
		pks2 := r2.PublicKeyShares[i]
		if err := comparePublicKeyShare(pks, pks2); err != nil {
			return err
		}
	}

	return nil
}

func makeRegistry(
	t *testing.T,
	g group.Group,
	threshold, maxParticipants uint16,
	keyShares []*secretsharing.KeyShare,
) *secretsharing.PublicKeyShareRegistry {
	registry := secretsharing.NewPublicKeyShareRegistry(g, threshold, maxParticipants)
	for _, keyShare := range keyShares {
		if err := registry.Add(keyShare.Public()); err != nil {
			t.Fatal(err)
		}
	}

	registry.GroupPublicKey = keyShares[0].GroupPublicKey

	return registry
}

func TestRegistry_Encoding(t *testing.T) {
	for _, g := range groups {
		t.Run(g.String(), func(t *testing.T) {
			// Shard the secret into shares
			shares, err := secretsharing.ShardAndCommit(g, nil, 3, 5)
			if err != nil {
				t.Fatal(err)
			}

			registry := makeRegistry(t, g, 3, 5, shares)

			// Bytes
			b := registry.Encode()
			r2 := new(secretsharing.PublicKeyShareRegistry)

			if err := r2.Decode(b); err != nil {
				t.Fatal(err)
			}

			if err := compareRegistries(registry, r2); err != nil {
				t.Fatal(err)
			}

			// JSON
			j, err := json.Marshal(registry)
			if err != nil {
				t.Fatal(err)
			}

			r2 = new(secretsharing.PublicKeyShareRegistry)
			if err := json.Unmarshal(j, r2); err != nil {
				t.Fatal(err)
			}

			if err = compareRegistries(registry, r2); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRegistry_Decode_Bad(t *testing.T) {
	errEncodingInvalidLength := errors.New("failed to decode PublicKeyShareRegistry: invalid encoding length")
	errInvalidGroup := errors.New("failed to decode PublicKeyShareRegistry: invalid group identifier")
	errEncodingPKSDuplication := errors.New(
		"failed to decode PublicKeyShareRegistry: multiple encoded public key shares with same ID",
	)

	for _, g := range groups {
		t.Run(g.String(), func(t *testing.T) {
			// Shard the secret into shares
			shares, err := secretsharing.ShardAndCommit(g, nil, 3, 5)
			if err != nil {
				t.Fatal(err)
			}

			registry := makeRegistry(t, g, 3, 5, shares)

			d := new(secretsharing.PublicKeyShareRegistry)
			badElement := getBadElement(t, g)

			// too short
			if err = d.Decode([]byte{1, 2, 3}); err == nil || err.Error() != errEncodingInvalidLength.Error() {
				t.Fatalf("expected error %q, got %q", errEncodingInvalidLength, err)
			}

			// invalid ciphersuite
			e := registry.Encode()
			e[0] = 2

			if err = d.Decode(e); err == nil || err.Error() != errInvalidGroup.Error() {
				t.Fatalf("expected error %q, got %q", errInvalidGroup, err)
			}

			// too short
			e = registry.Encode()
			l := len(e) - 5

			if err = d.Decode(e[:l]); err == nil || err.Error() != errEncodingInvalidLength.Error() {
				t.Fatalf("expected error %q, got %q", errEncodingInvalidLength, err)
			}

			// Decode: Bad public key
			e = registry.Encode()
			e = slices.Replace(e, 5, 5+g.ElementLength(), badElement...)
			expectedErrorPrefix := errors.New(
				"failed to decode PublicKeyShareRegistry: invalid group public key encoding: element Decode: ",
			)
			if err = d.Decode(e); err == nil || !strings.HasPrefix(err.Error(), expectedErrorPrefix.Error()) {
				t.Fatalf("expected error %q, got %q", expectedErrorPrefix, err)
			}

			// Decode: a faulty public key share, with a wrong group
			e = registry.Encode()
			e[5+g.ElementLength()] = 2
			expectedErrorPrefix = errors.New(
				"failed to decode PublicKeyShareRegistry: could not decode public key share ",
			)
			if err = d.Decode(e); err == nil || !strings.HasPrefix(err.Error(), expectedErrorPrefix.Error()) {
				t.Fatalf("expected error %q, got %q", expectedErrorPrefix, err)
			}

			// Decode: double entry, replacing the 2nd share with the third
			pks1 := registry.PublicKeyShares[1].Encode()
			pks2 := registry.PublicKeyShares[2].Encode()
			pks3 := registry.PublicKeyShares[3].Encode()
			start := 5 + g.ElementLength() + len(pks1)
			end := start + len(pks2)
			e = registry.Encode()

			// Since we're using a map, we're not ensured to have the same order in encoding. So we force
			// two consecutive writes.
			e = slices.Replace(e, start, end, pks3...)
			e = slices.Replace(e, end, end+len(pks3), pks3...)

			if err = d.Decode(e); err == nil || err.Error() != errEncodingPKSDuplication.Error() {
				t.Fatalf("expected error %q, got %q", errEncodingPKSDuplication, err)
			}

			// Hex: un-even length
			h := registry.Hex()
			expectedError := "failed to decode PublicKeyShareRegistry: encoding/hex: odd length hex string"
			if err = d.DecodeHex(h[:len(h)-1]); err == nil || err.Error() != expectedError {
				t.Fatalf("expected error %q, got %q", expectedError, err)
			}

			// JSON: bad json
			data, err := json.Marshal(registry)
			if err != nil {
				t.Fatal(err)
			}

			data = replaceStringInBytes(data, "\"group\"", "bad")
			expectedErrorPrefix = errors.New("invalid character 'b' looking for beginning of object key string")

			if err = json.Unmarshal(data, d); err == nil ||
				!strings.HasPrefix(err.Error(), expectedErrorPrefix.Error()) {
				t.Fatalf("expected error %q, got %q", expectedErrorPrefix, err)
			}

			// UnmarshallJSON: bad group
			data, err = json.Marshal(registry)
			if err != nil {
				t.Fatal(err)
			}

			data = replaceStringInBytes(data, fmt.Sprintf("\"group\":%d", registry.Group), "\"group\":2")
			if err = json.Unmarshal(data, d); err == nil || err.Error() != errInvalidGroup.Error() {
				t.Fatalf("expected error %q, got %q", errInvalidGroup, err)
			}

			// UnmarshallJSON: bad ciphersuite
			data, err = json.Marshal(registry)
			if err != nil {
				t.Fatal(err)
			}

			data = replaceStringInBytes(data, fmt.Sprintf("\"group\":%d", registry.Group), "\"group\":70")
			if err = json.Unmarshal(data, d); err == nil || err.Error() != errInvalidGroup.Error() {
				t.Fatalf("expected error %q, got %q", errInvalidGroup, err)
			}

			// UnmarshallJSON: bad ciphersuite
			data, err = json.Marshal(registry)
			if err != nil {
				t.Fatal(err)
			}

			data = replaceStringInBytes(data, fmt.Sprintf("\"group\":%d", g), "\"group\":17")
			if err = json.Unmarshal(data, d); err == nil || err.Error() != errInvalidGroup.Error() {
				t.Fatalf("expected error %q, got %q", errInvalidGroup, err)
			}

			// UnmarshallJSON: bad ciphersuite
			data, err = json.Marshal(registry)
			if err != nil {
				t.Fatal(err)
			}

			data = replaceStringInBytes(data, fmt.Sprintf("\"group\":%d", g), "\"group\":-1")
			expectedError = "failed to decode PublicKeyShareRegistry: failed to decode PublicKeyShare: invalid JSON encoding"
			if err = json.Unmarshal(data, d); err == nil || err.Error() != expectedError {
				t.Fatalf("expected error %q, got %q", expectedError, err)
			}

			// UnmarshallJSON: bad ciphersuite
			data, err = json.Marshal(registry)
			if err != nil {
				t.Fatal(err)
			}

			overflow := "9223372036854775808" // MaxInt64 + 1
			data = replaceStringInBytes(data, fmt.Sprintf("\"group\":%d", g), "\"group\":"+overflow)

			expectedErrorPrefix = errors.New(
				"failed to decode PublicKeyShareRegistry: failed to read Group: strconv.Atoi: parsing \"9223372036854775808\": value out of range",
			)

			if err = json.Unmarshal(data, d); err == nil ||
				!strings.HasPrefix(err.Error(), expectedErrorPrefix.Error()) {
				t.Fatalf("expected error %q, got %q", expectedErrorPrefix, err)
			}
		})
	}
}

func TestRegistry_JSON(t *testing.T) {
	for _, g := range groups {
		t.Run(g.String(), func(t *testing.T) {
			// Shard the secret into shares
			shares, err := secretsharing.ShardAndCommit(g, nil, 3, 5)
			if err != nil {
				t.Fatal(err)
			}

			registry := makeRegistry(t, g, 3, 5, shares)

			// JSON
			j, err := json.Marshal(registry)
			if err != nil {
				t.Fatal(err)
			}

			r2 := new(secretsharing.PublicKeyShareRegistry)
			if err := json.Unmarshal(j, r2); err != nil {
				t.Fatal(err)
			}

			if err = compareRegistries(registry, r2); err != nil {
				t.Fatal(err)
			}
		})
	}
}
