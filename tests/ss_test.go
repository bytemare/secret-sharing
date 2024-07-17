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
	threshold := uint(3)
	total := uint(5)

	for _, g := range groups {
		t.Run(g.String(), func(t *testing.T) {
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
				shares[i] = &secretsharing.KeyShare{PublicKeyShare: secretsharing.PublicKeyShare{ID: i64}}
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

			// Provide the all elements of the polynomial with the prepending secret
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

			shares, err := secretsharing.ShardAndCommit(g, secret, threshold, total)
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
	threshold := uint(2)
	total := uint(3)

	for _, g := range groups {
		t.Run(g.String(), func(tt *testing.T) {
			secret := g.NewScalar().Random()

			shares, err := secretsharing.ShardAndCommit(g, secret, threshold, total)
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
	threshold := uint(2)
	total := threshold - 1
	expected := "number of shares must be equal or greater than the threshold"

	for _, g := range groups {
		t.Run(g.String(), func(tt *testing.T) {
			secret := g.NewScalar().Random()

			if _, err := secretsharing.Shard(g, secret, threshold, total); err == nil || err.Error() != expected {
				t.Fatalf("expected error %q, got %q", expected, err)
			}

			if _, err := secretsharing.ShardAndCommit(g, secret, threshold, total); err == nil ||
				err.Error() != expected {
				t.Fatalf("expected error %q, got %q", expected, err)
			}

			if _, _, err := secretsharing.ShardReturnPolynomial(g, secret, threshold, total); err == nil ||
				err.Error() != expected {
				t.Fatalf("expected error %q, got %q", expected, err)
			}
		})
	}
}

func testBadPolynomial(g group.Group, threshold, max uint, p secretsharing.Polynomial, s ...*group.Scalar) error {
	var secret *group.Scalar
	if len(s) == 0 {
		secret = g.NewScalar().Random()
	} else {
		secret = s[0]
	}

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
		t.Run(g.String(), func(t *testing.T) {
			// Test polynomial with first coefficient not set to the secret
			polyNoSecret := secretsharing.NewPolynomial(threshold)
			polyNoSecret[0] = g.NewScalar().Random()
			polyNoSecret[1] = g.NewScalar().Random()
			polyNoSecret[2] = g.NewScalar().Random()

			t.Run(g.String(), func(tt *testing.T) {
				if err := testBadPolynomial(g, threshold, total, polyNoSecret); err == nil || err.Error() != expected {
					t.Fatalf("expected error %q, got %q", expected, err)
				}
			})
		})
	}
}

func TestBadPolynomial_NilCoeff(t *testing.T) {
	threshold := uint(3)
	total := uint(5)
	expected := "the polynomial has a nil coefficient"

	for _, g := range groups {
		t.Run(g.String(), func(t *testing.T) {
			// Test polynomial with a nil coefficient
			polyNilCoeff := make(secretsharing.Polynomial, threshold)
			polyNilCoeff[0] = g.NewScalar().Random()
			polyNilCoeff[1] = nil
			polyNilCoeff[2] = g.NewScalar().Random()

			t.Run(g.String(), func(tt *testing.T) {
				if err := testBadPolynomial(g, threshold, total, polyNilCoeff, polyNilCoeff[0]); err == nil ||
					err.Error() != expected {
					t.Fatalf("expected error %q, got %q", expected, err)
				}
			})
		})
	}
}

func TestBadPolynomial_ZeroCoeff(t *testing.T) {
	threshold := uint(3)
	total := uint(5)
	expected := "one of the polynomial's coefficients is zero"

	for _, g := range groups {
		t.Run(g.String(), func(t *testing.T) {
			// Test polynomial with a zero coefficient
			polyZeroCoeff := make(secretsharing.Polynomial, threshold)
			polyZeroCoeff[0] = g.NewScalar().Random()
			polyZeroCoeff[1] = g.NewScalar().Zero()
			polyZeroCoeff[2] = g.NewScalar().Random()

			t.Run(g.String(), func(tt *testing.T) {
				if err := testBadPolynomial(g, threshold, total, polyZeroCoeff, polyZeroCoeff[0]); err != nil &&
					err.Error() != expected {
					t.Fatalf("expected error %q, got %q", expected, err)
				}
			})
		})
	}
}

func TestBadPolynomial_WrongSize(t *testing.T) {
	threshold := uint(2)
	total := uint(3)
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
				if err := testBadPolynomial(g, threshold, total, polyShort); err != nil && err.Error() != expected {
					t.Fatalf("expected error %q, got %q", expected, err)
				}

				if err := testBadPolynomial(g, threshold, total, polyLong); err != nil && err.Error() != expected {
					t.Fatalf("expected error %q, got %q", expected, err)
				}
			})
		})
	}
}

func TestCombine_TooFewShares(t *testing.T) {
	// threshold := uint(2)
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
	threshold := uint(3) // threshold is the minimum amount of necessary shares to recombine the secret
	total := uint(7)     // the total amount of key share-holders

	for _, g := range groups {
		t.Run(g.String(), func(t *testing.T) {
			// This is the global secret to be shared
			secret := g.NewScalar().Random()

			// Shard the secret into shares
			shares, err := secretsharing.ShardAndCommit(g, secret, threshold, total)
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
	threshold := uint(5)
	shareholders := uint(7)

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

func TestEncoding(t *testing.T) {
	threshold := uint(3) // threshold is the minimum amount of necessary shares to recombine the secret
	total := uint(7)     // the total amount of key share-holders

	for _, g := range groups {
		t.Run(g.String(), func(t *testing.T) {
			// This is the global secret to be shared
			secret := g.NewScalar().Random()

			// Shard the secret into shares
			shares, err := secretsharing.ShardAndCommit(g, secret, threshold, total)
			if err != nil {
				t.Fatal(err)
			}

			b := shares[0].Encode()

			decoded := &secretsharing.KeyShare{}
			if err = decoded.Decode(b); err != nil {
				t.Fatal(err)
			}

			if err = compareKeyShares(shares[0], decoded); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestJSONEncoding(t *testing.T) {
	threshold := uint(3) // threshold is the minimum amount of necessary shares to recombine the secret
	total := uint(7)     // the total amount of key share-holders

	for _, g := range groups {
		t.Run(g.String(), func(t *testing.T) {
			// This is the global secret to be shared
			secret := g.NewScalar().Random()

			// Shard the secret into shares
			shares, err := secretsharing.ShardAndCommit(g, secret, threshold, total)
			if err != nil {
				t.Fatal(err)
			}

			j, err := json.Marshal(shares[0])
			if err != nil {
				t.Fatal(err)
			}

			decoded := &secretsharing.KeyShare{}
			if err = json.Unmarshal(j, decoded); err != nil {
				t.Fatal(err)
			}

			if err = compareKeyShares(shares[0], decoded); err != nil {
				t.Fatal(err)
			}
		})
	}
}

type serde interface {
	Decode([]byte) error
	UnmarshalJSON(data []byte) error
}

func testDecode(t *testing.T, encoded []byte, s serde, expectedError error) {
	if err := s.Decode(encoded); err == nil || err.Error() != expectedError.Error() {
		t.Fatalf("expected error %q, got %q", expectedError, err)
	}
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
	threshold := uint(1)
	total := uint(2)

	errEncodingInvalidLength := errors.New("invalid encoding length")
	errEncodingInvalidGroup := errors.New("invalid group identifier")
	errEncodingInvalidJSONEncoding := errors.New("invalid JSON encoding")

	for _, g := range groups {
		t.Run(g.String(), func(t *testing.T) {
			secret := g.NewScalar().Random()
			shares, err := secretsharing.ShardAndCommit(g, secret, threshold, total)
			if err != nil {
				t.Fatal(err)
			}

			// Decode: empty
			testDecode(t, nil, new(secretsharing.PublicKeyShare), errEncodingInvalidLength)

			// Decode: bad group
			encoded := shares[0].Public().Encode()
			encoded[0] = 0
			testDecode(t, encoded, new(secretsharing.PublicKeyShare), errEncodingInvalidGroup)

			encoded[0] = 255
			testDecode(t, encoded, new(secretsharing.PublicKeyShare), errEncodingInvalidGroup)

			// Decode: header too short
			encoded = shares[0].Public().Encode()
			testDecode(t, encoded[:12], new(secretsharing.PublicKeyShare), errEncodingInvalidLength)

			// Decode: Bad Length
			testDecode(t, encoded[:25], new(secretsharing.PublicKeyShare), errEncodingInvalidLength)

			// Decode: Bad public key
			badElement := getBadElement(t, g)
			encoded = slices.Replace(encoded, 13, 13+g.ElementLength(), badElement...)
			expectedErrorPrefix := errors.New("failed to decode public key")
			if err := new(secretsharing.PublicKeyShare).Decode(encoded); err == nil ||
				!strings.HasPrefix(err.Error(), expectedErrorPrefix.Error()) {
				t.Fatalf("expected error %q, got %q", expectedErrorPrefix, err)
			}

			// Decode: bad commitment
			encoded = shares[0].Public().Encode()
			badElement = getBadElement(t, g)
			offset := 13 + g.ElementLength()
			encoded = slices.Replace(encoded, offset, offset+g.ElementLength(), badElement...)

			// UnmarshallJSON: bad group, no group
			j, err := json.Marshal(shares[0])
			if err != nil {
				t.Fatal(err)
			}

			s := string(j)
			s = strings.Replace(s, "\"group\"", "\"nope\"", 1)

			if err := json.Unmarshal([]byte(s), new(secretsharing.PublicKeyShare)); err == nil ||
				err.Error() != errEncodingInvalidJSONEncoding.Error() {
				t.Fatalf("expected error %q, got %q", errEncodingInvalidJSONEncoding, err)
			}

			// UnmarshallJSON: bad group
			j, err = json.Marshal(shares[0])
			if err != nil {
				t.Fatal(err)
			}

			s = string(j)
			s = strings.Replace(s, fmt.Sprintf("\"group\":%d", g), "\"group\":-1", 1)

			if err := json.Unmarshal([]byte(s), new(secretsharing.PublicKeyShare)); err == nil ||
				err.Error() != errEncodingInvalidJSONEncoding.Error() {
				t.Fatalf("expected error %q, got %q", errEncodingInvalidJSONEncoding, err)
			}

			// UnmarshallJSON: bad group
			j, err = json.Marshal(shares[0])
			if err != nil {
				t.Fatal(err)
			}

			s = string(j)
			s = strings.Replace(s, fmt.Sprintf("\"group\":%d", g), "\"group\":17", 1)

			if err := json.Unmarshal([]byte(s), new(secretsharing.PublicKeyShare)); err == nil ||
				err.Error() != errEncodingInvalidGroup.Error() {
				t.Fatalf("expected error %q, got %q", errEncodingInvalidGroup, err)
			}

			// UnmarshallJSON: no commitment
			j, err = json.Marshal(shares[0])
			if err != nil {
				t.Fatal(err)
			}

			s = string(j)
			s = strings.Replace(s, "\"commitment\"", "\"nope\"", 1)

			if err := json.Unmarshal([]byte(s), new(secretsharing.PublicKeyShare)); err == nil ||
				err.Error() != errEncodingInvalidJSONEncoding.Error() {
				t.Fatalf("expected error %q, got %q", errEncodingInvalidJSONEncoding, err)
			}
		})
	}
}

func TestEncoding_KeyShare_Bad(t *testing.T) {
	threshold := uint(1)
	total := uint(2)

	errEncodingInvalidLength := errors.New("invalid encoding length")
	errEncodingInvalidGroup := errors.New("invalid group identifier")
	errEncodingInvalidJSONEncoding := errors.New("invalid JSON encoding")

	for _, g := range groups {
		t.Run(g.String(), func(t *testing.T) {
			secret := g.NewScalar().Random()
			shares, err := secretsharing.ShardAndCommit(g, secret, threshold, total)
			if err != nil {
				t.Fatal(err)
			}

			// Decode: empty
			testDecode(t, nil, new(secretsharing.KeyShare), errEncodingInvalidLength)

			// Decode: bad group
			encoded := shares[0].Encode()
			encoded[0] = 0
			testDecode(t, encoded, new(secretsharing.KeyShare), errEncodingInvalidGroup)

			encoded[0] = 255
			testDecode(t, encoded, new(secretsharing.KeyShare), errEncodingInvalidGroup)

			// Decode: header too short
			encoded = shares[0].Encode()
			testDecode(t, encoded[:12], new(secretsharing.KeyShare), errEncodingInvalidLength)

			// Decode: Bad Length
			testDecode(t, encoded[:25], new(secretsharing.KeyShare), errEncodingInvalidLength)

			// Decode: Bad public key share
			offset := 13
			encoded = shares[0].Encode()
			badElement := getBadElement(t, g)
			encoded = slices.Replace(encoded, offset, offset+g.ElementLength(), badElement...)

			expectedErrorPrefix := errors.New("failed to decode public key: ")
			if err := new(secretsharing.KeyShare).Decode(encoded); err == nil ||
				!strings.HasPrefix(err.Error(), expectedErrorPrefix.Error()) {
				t.Fatalf("expected error %q, got %q", expectedErrorPrefix, err)
			}

			// Decode: Bad scalar
			offset = 1 + 8 + 4 + g.ElementLength() + len(shares[0].Commitment)*g.ElementLength()
			badScalar := getBadScalar(g)
			encoded = shares[0].Encode()
			encoded = slices.Replace(encoded, offset, offset+g.ScalarLength(), badScalar...)
			expectedErrorPrefix = errors.New("failed to decode Secret in KeyShare")
			if err := new(secretsharing.KeyShare).Decode(encoded); err == nil ||
				!strings.HasPrefix(err.Error(), expectedErrorPrefix.Error()) {
				t.Fatalf("expected error %q, got %q", expectedErrorPrefix, err)
			}

			// Decode: bad group public key
			offset += g.ScalarLength()
			encoded = shares[0].Encode()
			badElement = getBadElement(t, g)
			encoded = slices.Replace(encoded, offset, offset+g.ElementLength(), badElement...)

			expectedErrorPrefix = errors.New("failed to decode GroupPublicKey in KeyShare")
			if err := new(secretsharing.KeyShare).Decode(encoded); err == nil ||
				!strings.HasPrefix(err.Error(), expectedErrorPrefix.Error()) {
				t.Fatalf("expected error %q, got %q", expectedErrorPrefix, err)
			}

			// UnmarshallJSON: bad group encoding
			j, err := json.Marshal(shares[0])
			if err != nil {
				t.Fatal(err)
			}

			s := string(j)
			s = strings.Replace(s, fmt.Sprintf("\"group\":%d", g), "\"group\":-1", 1)

			if err := json.Unmarshal([]byte(s), new(secretsharing.KeyShare)); err == nil ||
				err.Error() != errEncodingInvalidJSONEncoding.Error() {
				t.Fatalf("expected error %q, got %q", errEncodingInvalidJSONEncoding, err)
			}
		})
	}
}
