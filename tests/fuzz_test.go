// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package secretsharing_test

import (
	"encoding/json"
	"testing"

	"github.com/bytemare/ecc"

	"github.com/bytemare/secret-sharing/keys"

	secretsharing "github.com/bytemare/secret-sharing"
)

const maxFuzzThreshold = 4

func makeFuzzMaterial(f *testing.F, g ecc.Group) ([]*keys.KeyShare, *keys.PublicKeyShareRegistry) {
	f.Helper()

	shares, err := secretsharing.ShardAndCommit(g, g.NewScalar().SetUInt64(42), 2, 3)
	if err != nil {
		f.Fatal(err)
	}

	public := make([]*keys.PublicKeyShare, len(shares))
	for i, share := range shares {
		public[i] = share.PublicKeyShare()
	}
	registry, err := keys.NewPublicKeyShareRegistry(g, 2, 3, shares[0].VerificationKey(), public)
	if err != nil {
		f.Fatal(err)
	}

	return shares, registry
}

func addJSONSeed(f *testing.F, g ecc.Group, in any) {
	f.Helper()

	data, err := json.Marshal(in)
	if err != nil {
		f.Fatal(err)
	}

	f.Add(byte(g), data)
}

func fuzzThresholds(thresholdSeed, extraSeed byte) (uint16, uint16) {
	threshold := uint16(thresholdSeed%maxFuzzThreshold) + 1
	total := threshold + uint16(extraSeed%maxFuzzThreshold)

	return threshold, total
}

func fuzzNonZeroScalar(g ecc.Group, value uint64) *ecc.Scalar {
	return g.NewScalar().SetUInt64(value%1024 + 1)
}

func makeFuzzPolynomial(g ecc.Group, threshold uint16, secret uint64, coeffs []byte) secretsharing.Polynomial {
	polynomial := secretsharing.NewPolynomial(threshold)
	polynomial[0] = fuzzNonZeroScalar(g, secret)

	for i := uint16(1); i < threshold; i++ {
		value := uint64(i) + 1
		if len(coeffs) != 0 {
			value += uint64(coeffs[(int(i)-1)%len(coeffs)])
		}

		if i < threshold-1 && value%5 == 0 {
			polynomial[i] = g.NewScalar().Zero()
			continue
		}

		polynomial[i] = fuzzNonZeroScalar(g, value)
	}

	return polynomial
}

func comparePolynomials(p1, p2 secretsharing.Polynomial) bool {
	if len(p1) != len(p2) {
		return false
	}

	for i := range p1 {
		if !p1[i].Equal(p2[i]) {
			return false
		}
	}

	return true
}

func assertPublicKeyShareRoundTrip(t *testing.T, share *keys.PublicKeyShare) {
	t.Helper()

	decoded := new(keys.PublicKeyShare)
	if err := decoded.Decode(share.Encode()); err != nil {
		t.Fatal(err)
	}

	if err := comparePublicKeyShare(share, decoded, true); err != nil {
		t.Fatal(err)
	}

	decodedHex := new(keys.PublicKeyShare)
	if err := decodedHex.DecodeHex(share.Hex()); err != nil {
		t.Fatal(err)
	}

	if err := comparePublicKeyShare(share, decodedHex, true); err != nil {
		t.Fatal(err)
	}
}

func assertKeyShareRoundTrip(t *testing.T, share *keys.KeyShare) {
	t.Helper()

	decoded := new(keys.KeyShare)
	if err := decoded.Decode(share.Encode()); err != nil {
		t.Fatal(err)
	}

	if err := compareKeyShares(share, decoded, true); err != nil {
		t.Fatal(err)
	}

	decodedHex := new(keys.KeyShare)
	if err := decodedHex.DecodeHex(share.Hex()); err != nil {
		t.Fatal(err)
	}

	if err := compareKeyShares(share, decodedHex, true); err != nil {
		t.Fatal(err)
	}
}

func assertRegistryRoundTrip(t *testing.T, registry *keys.PublicKeyShareRegistry) {
	t.Helper()

	decoded := new(keys.PublicKeyShareRegistry)
	if err := decoded.Decode(registry.Encode()); err != nil {
		t.Fatal(err)
	}

	if err := compareRegistries(registry, decoded); err != nil {
		t.Fatal(err)
	}

	decodedHex := new(keys.PublicKeyShareRegistry)
	if err := decodedHex.DecodeHex(registry.Hex()); err != nil {
		t.Fatal(err)
	}

	if err := compareRegistries(registry, decodedHex); err != nil {
		t.Fatal(err)
	}
}

// FuzzPublicKeyShareJSONDecode fuzzes inferred and group-pinned PublicKeyShare JSON decoding.
func FuzzPublicKeyShareJSONDecode(f *testing.F) {
	for _, g := range groups {
		shares, _ := makeFuzzMaterial(f, g)
		addJSONSeed(f, g, shares[0].PublicKeyShare())
	}

	f.Fuzz(func(t *testing.T, groupID byte, data []byte) {
		g := ecc.Group(groupID)
		if !g.Available() {
			return
		}

		inferred := new(keys.PublicKeyShare)
		if err := json.Unmarshal(data, inferred); err == nil {
			if !inferred.Group().Available() || inferred.PublicKey() == nil {
				t.Fatalf("inferred public key share has invalid group or nil public key")
			}

			encoded, err := json.Marshal(inferred)
			if err != nil {
				t.Fatal(err)
			}
			roundTrip := new(keys.PublicKeyShare)
			if err = json.Unmarshal(encoded, roundTrip); err != nil {
				t.Fatal(err)
			}
			if err = comparePublicKeyShare(inferred, roundTrip, true); err != nil {
				t.Fatal(err)
			}
		}

		pinned := keys.NewPublicKeyShareReceiver(g)
		if err := json.Unmarshal(data, pinned); err == nil {
			if pinned.Group() != g || pinned.PublicKey() == nil {
				t.Fatalf("pinned public key share has invalid group or nil public key")
			}

			encoded, err := json.Marshal(pinned)
			if err != nil {
				t.Fatal(err)
			}
			roundTrip := keys.NewPublicKeyShareReceiver(g)
			if err = json.Unmarshal(encoded, roundTrip); err != nil {
				t.Fatal(err)
			}
			if err = comparePublicKeyShare(pinned, roundTrip, true); err != nil {
				t.Fatal(err)
			}
		}
	})
}

// FuzzKeyShareJSONDecode fuzzes inferred and group-pinned KeyShare JSON decoding.
func FuzzKeyShareJSONDecode(f *testing.F) {
	for _, g := range groups {
		shares, _ := makeFuzzMaterial(f, g)
		addJSONSeed(f, g, shares[0])
	}

	f.Fuzz(func(t *testing.T, groupID byte, data []byte) {
		g := ecc.Group(groupID)
		if !g.Available() {
			return
		}

		inferred := new(keys.KeyShare)
		if err := json.Unmarshal(data, inferred); err == nil {
			if !inferred.Group().Available() ||
				inferred.SecretKey() == nil ||
				inferred.VerificationKey() == nil ||
				inferred.PublicKeyShare().PublicKey() == nil {
				t.Fatalf("inferred key share has invalid group or nil key material")
			}

			encoded, err := json.Marshal(inferred)
			if err != nil {
				t.Fatal(err)
			}
			roundTrip := new(keys.KeyShare)
			if err = json.Unmarshal(encoded, roundTrip); err != nil {
				t.Fatal(err)
			}
			if err = compareKeyShares(inferred, roundTrip, true); err != nil {
				t.Fatal(err)
			}
		}

		pinned := keys.NewKeyShareReceiver(g)
		if err := json.Unmarshal(data, pinned); err == nil {
			if pinned.Group() != g ||
				pinned.SecretKey() == nil ||
				pinned.VerificationKey() == nil ||
				pinned.PublicKeyShare().PublicKey() == nil {
				t.Fatalf("pinned key share has invalid group or nil key material")
			}

			encoded, err := json.Marshal(pinned)
			if err != nil {
				t.Fatal(err)
			}
			roundTrip := keys.NewKeyShareReceiver(g)
			if err = json.Unmarshal(encoded, roundTrip); err != nil {
				t.Fatal(err)
			}
			if err = compareKeyShares(pinned, roundTrip, true); err != nil {
				t.Fatal(err)
			}
		}
	})
}

// FuzzPublicKeyShareRegistryJSONDecode fuzzes inferred and group-pinned registry JSON decoding.
func FuzzPublicKeyShareRegistryJSONDecode(f *testing.F) {
	for _, g := range groups {
		_, registry := makeFuzzMaterial(f, g)
		addJSONSeed(f, g, registry)
	}

	f.Fuzz(func(t *testing.T, groupID byte, data []byte) {
		g := ecc.Group(groupID)
		if !g.Available() {
			return
		}

		inferred := new(keys.PublicKeyShareRegistry)
		if err := json.Unmarshal(data, inferred); err == nil {
			if !inferred.Group().Available() ||
				inferred.VerificationKey() == nil ||
				len(inferred.Shares()) != int(inferred.Total()) {
				t.Fatalf("inferred registry has invalid group, nil verification key, or inconsistent total")
			}

			encoded, err := json.Marshal(inferred)
			if err != nil {
				t.Fatal(err)
			}
			roundTrip := new(keys.PublicKeyShareRegistry)
			if err = json.Unmarshal(encoded, roundTrip); err != nil {
				t.Fatal(err)
			}
			if err = compareRegistries(inferred, roundTrip); err != nil {
				t.Fatal(err)
			}
		}

		pinned := keys.NewPublicKeyShareRegistryReceiver(g)
		if err := json.Unmarshal(data, pinned); err == nil {
			if pinned.Group() != g ||
				pinned.VerificationKey() == nil ||
				len(pinned.Shares()) != int(pinned.Total()) {
				t.Fatalf("pinned registry has invalid group, nil verification key, or inconsistent total")
			}

			encoded, err := json.Marshal(pinned)
			if err != nil {
				t.Fatal(err)
			}
			roundTrip := keys.NewPublicKeyShareRegistryReceiver(g)
			if err = json.Unmarshal(encoded, roundTrip); err != nil {
				t.Fatal(err)
			}
			if err = compareRegistries(pinned, roundTrip); err != nil {
				t.Fatal(err)
			}
		}
	})
}

// FuzzCompactDecoders fuzzes compact byte and hexadecimal decoders for all public key container types.
func FuzzCompactDecoders(f *testing.F) {
	for _, g := range groups {
		shares, registry := makeFuzzMaterial(f, g)
		f.Add(shares[0].PublicKeyShare().Encode())
		f.Add(shares[0].Encode())
		f.Add(registry.Encode())
		f.Add([]byte(shares[0].PublicKeyShare().Hex()))
		f.Add([]byte(shares[0].Hex()))
		f.Add([]byte(registry.Hex()))
	}
	f.Add([]byte("zz"))

	f.Fuzz(func(t *testing.T, data []byte) {
		publicShare := new(keys.PublicKeyShare)
		if err := publicShare.Decode(data); err == nil {
			assertPublicKeyShareRoundTrip(t, publicShare)
		}
		if err := publicShare.DecodeHex(string(data)); err == nil {
			assertPublicKeyShareRoundTrip(t, publicShare)
		}

		keyShare := new(keys.KeyShare)
		if err := keyShare.Decode(data); err == nil {
			assertKeyShareRoundTrip(t, keyShare)
		}
		if err := keyShare.DecodeHex(string(data)); err == nil {
			assertKeyShareRoundTrip(t, keyShare)
		}

		registry := new(keys.PublicKeyShareRegistry)
		if err := registry.Decode(data); err == nil {
			assertRegistryRoundTrip(t, registry)
		}
		if err := registry.DecodeHex(string(data)); err == nil {
			assertRegistryRoundTrip(t, registry)
		}
	})
}

// FuzzShardAndCombine fuzzes the public sharding workflows and secret recombination invariants.
func FuzzShardAndCombine(f *testing.F) {
	for _, g := range groups {
		f.Add(byte(g), byte(1), byte(2), uint64(42), []byte{3, 4, 5})
	}

	f.Fuzz(func(t *testing.T, groupID, thresholdSeed, extraSeed byte, secret uint64, coeffs []byte) {
		g := ecc.Group(groupID)
		if !g.Available() {
			return
		}

		threshold, total := fuzzThresholds(thresholdSeed, extraSeed)
		polynomial := makeFuzzPolynomial(g, threshold, secret, coeffs)

		plainShares, err := secretsharing.Shard(g, polynomial[0], threshold, total, polynomial...)
		if err != nil {
			t.Fatal(err)
		}

		committedShares, err := secretsharing.ShardAndCommit(g, polynomial[0], threshold, total, polynomial...)
		if err != nil {
			t.Fatal(err)
		}

		returnedShares, returnedPolynomial, err := secretsharing.ShardReturnPolynomial(
			g,
			polynomial[0],
			threshold,
			total,
			polynomial...,
		)
		if err != nil {
			t.Fatal(err)
		}

		committedReturnedShares, committedReturnedPolynomial, err := secretsharing.ShardAndCommitAndReturnPolynomial(
			g,
			polynomial[0],
			threshold,
			total,
			polynomial...,
		)
		if err != nil {
			t.Fatal(err)
		}

		if len(plainShares) != int(total) ||
			len(committedShares) != int(total) ||
			len(returnedShares) != int(total) ||
			len(committedReturnedShares) != int(total) {
			t.Fatalf("unexpected share count")
		}

		if !comparePolynomials(polynomial, returnedPolynomial) ||
			!comparePolynomials(polynomial, committedReturnedPolynomial) {
			t.Fatalf("returned polynomial differs from the provided polynomial")
		}

		for i := range plainShares {
			if err = compareKeyShares(plainShares[i], returnedShares[i], true); err != nil {
				t.Fatal(err)
			}
			if err = compareKeyShares(committedShares[i], committedReturnedShares[i], true); err != nil {
				t.Fatal(err)
			}
			if err = compareKeyShares(plainShares[i], committedShares[i], false); err != nil {
				t.Fatal(err)
			}

			if plainShares[i].Group() != g ||
				plainShares[i].Identifier() != uint16(i+1) ||
				plainShares[i].SecretKey() == nil ||
				plainShares[i].PublicKeyShare() == nil {
				t.Fatalf("key share accessors returned inconsistent values")
			}
		}

		recovered, err := secretsharing.CombineShares(plainShares[:threshold], threshold)
		if err != nil {
			t.Fatal(err)
		}
		if !recovered.Equal(polynomial[0]) {
			t.Fatalf("threshold shares did not recover the secret")
		}

		recovered, err = secretsharing.CombineShares(plainShares, threshold)
		if err != nil {
			t.Fatal(err)
		}
		if !recovered.Equal(polynomial[0]) {
			t.Fatalf("all shares did not recover the secret")
		}
	})
}

// FuzzPolynomialOperations fuzzes public polynomial constructors, validation, evaluation, and interpolation helpers.
func FuzzPolynomialOperations(f *testing.F) {
	for _, g := range groups {
		f.Add(byte(g), byte(3), uint16(7), uint16(5))
	}

	f.Fuzz(func(t *testing.T, groupID, countSeed byte, offset, eval uint16) {
		g := ecc.Group(groupID)
		if !g.Available() {
			return
		}

		count := uint16(countSeed%8) + 1
		base := offset%60000 + 1
		ids := make([]uint16, count)
		for i := range count {
			id := base + i
			ids[i] = id
		}

		fromInts, err := secretsharing.NewPolynomialFromIntegers(g, ids)
		if err != nil {
			t.Fatal(err)
		}

		fromList, err := secretsharing.NewPolynomialFromListFunc(
			g,
			ids,
			func(id uint16) *ecc.Scalar {
				return g.NewScalar().SetUInt64(uint64(id))
			},
		)
		if err != nil {
			t.Fatal(err)
		}

		if !comparePolynomials(fromInts, fromList) {
			t.Fatalf("polynomial constructors disagree")
		}
		if err := fromInts.Verify(); err != nil {
			t.Fatal(err)
		}
		if err := fromInts.VerifyInterpolationIDs(); err != nil {
			t.Fatal(err)
		}

		weights := g.NewScalar().Zero()
		for _, id := range fromInts {
			if err := fromInts.VerifyInterpolatingInput(id); err != nil {
				t.Fatal(err)
			}

			weight, err := fromInts.DeriveInterpolatingValue(g, id)
			if err != nil {
				t.Fatal(err)
			}
			weights.Add(weight)
		}
		if !weights.Equal(g.NewScalar().One()) {
			t.Fatalf("interpolation weights do not sum to one")
		}

		x := g.NewScalar().SetUInt64(uint64(eval))
		want := g.NewScalar().Zero()
		power := g.NewScalar().One()
		for _, coeff := range fromInts {
			want.Add(coeff.Copy().Multiply(power))
			power.Multiply(x)
		}
		if got := fromInts.Evaluate(x); !got.Equal(want) {
			t.Fatalf("polynomial evaluation mismatch")
		}
	})
}

// FuzzCommitmentVerification fuzzes commitment derivation and public-key verification invariants.
func FuzzCommitmentVerification(f *testing.F) {
	for _, g := range groups {
		f.Add(byte(g), byte(2), byte(4), uint64(42), []byte{6, 7, 8})
	}

	f.Fuzz(func(t *testing.T, groupID, thresholdSeed, idSeed byte, secret uint64, coeffs []byte) {
		g := ecc.Group(groupID)
		if !g.Available() {
			return
		}

		threshold, _ := fuzzThresholds(thresholdSeed, 0)
		polynomial := makeFuzzPolynomial(g, threshold, secret, coeffs)
		commitment, err := secretsharing.Commit(g, polynomial)
		if err != nil {
			t.Fatal(err)
		}
		id := uint16(idSeed%8) + 1

		want := g.Base().Multiply(polynomial.Evaluate(g.NewScalar().SetUInt64(uint64(id))))
		got, err := secretsharing.PubKeyForCommitment(g, id, commitment)
		if err != nil {
			t.Fatal(err)
		}
		if !got.Equal(want) {
			t.Fatalf("commitment-derived public key mismatch")
		}
		if !secretsharing.Verify(g, id, want, commitment) {
			t.Fatalf("valid public key did not verify")
		}

		share, err := keys.NewPublicKeyShare(g, id, want, commitment)
		if err != nil {
			t.Fatal(err)
		}
		if !secretsharing.VerifyPublicKeyShare(share) {
			t.Fatalf("valid public key share did not verify")
		}

		wrong := want.Copy().Add(g.Base())
		if secretsharing.Verify(g, id, wrong, commitment) {
			t.Fatalf("invalid public key verified")
		}

		broken := append([]*ecc.Element(nil), commitment...)
		broken[int(idSeed)%len(broken)] = nil
		if _, err = secretsharing.PubKeyForCommitment(g, id, broken); err == nil {
			t.Fatalf("nil commitment element was accepted")
		}
		if secretsharing.Verify(g, id, want, broken) {
			t.Fatalf("verification succeeded with a nil commitment element")
		}
	})
}

// FuzzRegistryOperations fuzzes registry construction, lookup, and public-key verification behavior.
func FuzzRegistryOperations(f *testing.F) {
	for _, g := range groups {
		f.Add(byte(g), byte(2), byte(3), byte(1), uint64(42), []byte{9, 10, 11})
	}

	f.Fuzz(func(
		t *testing.T,
		groupID, thresholdSeed, extraSeed, lookupSeed byte,
		secret uint64,
		coeffs []byte,
	) {
		g := ecc.Group(groupID)
		if !g.Available() {
			return
		}

		threshold, total := fuzzThresholds(thresholdSeed, extraSeed)
		polynomial := makeFuzzPolynomial(g, threshold, secret, coeffs)
		shares, err := secretsharing.ShardAndCommit(g, polynomial[0], threshold, total, polynomial...)
		if err != nil {
			t.Fatal(err)
		}

		public := make([]*keys.PublicKeyShare, len(shares))
		for i, share := range shares {
			public[i] = share.PublicKeyShare()
		}
		registry, err := keys.NewPublicKeyShareRegistry(g, threshold, total, shares[0].VerificationKey(), public)
		if err != nil {
			t.Fatal(err)
		}

		index := int(lookupSeed) % len(shares)
		share := shares[index].PublicKeyShare()
		got := registry.Get(share.Identifier())
		if got == nil {
			t.Fatalf("registered share was not found")
		}
		if err = comparePublicKeyShare(share, got, true); err != nil {
			t.Fatal(err)
		}
		if err = registry.ContainsPublicKey(share.Identifier(), share.PublicKey()); err != nil {
			t.Fatal(err)
		}
		if err = registry.ContainsPublicKey(share.Identifier(), nil); err == nil {
			t.Fatalf("nil public key was accepted")
		}

		wrong := share.PublicKey().Add(g.Base())
		if err = registry.ContainsPublicKey(share.Identifier(), wrong); err == nil {
			t.Fatalf("wrong public key was accepted")
		}

		unknownID := total + 1
		if registry.Get(unknownID) != nil {
			t.Fatalf("unknown identifier resolved to a share")
		}
		if err = registry.ContainsPublicKey(unknownID, share.PublicKey()); err == nil {
			t.Fatalf("unknown identifier verified")
		}
		if _, err = keys.NewPublicKeyShareRegistry(
			g,
			threshold,
			total,
			shares[0].VerificationKey(),
			append(public, share),
		); err == nil {
			t.Fatalf("registry constructor accepted a duplicate share")
		}
	})
}
