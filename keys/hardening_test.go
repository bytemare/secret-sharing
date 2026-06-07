// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package keys_test

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"math"
	"testing"

	"github.com/bytemare/ecc"

	"github.com/bytemare/secret-sharing/keys"

	secretsharing "github.com/bytemare/secret-sharing"
)

const compactHeaderLength = 5

func mustShares(t *testing.T, group ecc.Group, threshold, total uint16, secret uint64) []*keys.KeyShare {
	t.Helper()

	shares, err := secretsharing.ShardAndCommit(
		group,
		group.NewScalar().SetUInt64(secret),
		threshold,
		total,
	)
	if err != nil {
		t.Fatal(err)
	}

	return shares
}

func mustSharesWithCoefficient(t *testing.T, group ecc.Group, secret, coefficient uint64) []*keys.KeyShare {
	t.Helper()

	secretScalar := group.NewScalar().SetUInt64(secret)
	polynomial := []*ecc.Scalar{
		secretScalar.Copy(),
		group.NewScalar().SetUInt64(coefficient),
	}
	shares, err := secretsharing.ShardAndCommit(group, secretScalar, 2, 2, polynomial...)
	if err != nil {
		t.Fatal(err)
	}

	return shares
}

func publicShares(shares []*keys.KeyShare) []*keys.PublicKeyShare {
	public := make([]*keys.PublicKeyShare, len(shares))
	for i, share := range shares {
		public[i] = share.PublicKeyShare()
	}

	return public
}

func mustRegistry(t *testing.T, shares []*keys.KeyShare, threshold, total uint16) *keys.PublicKeyShareRegistry {
	t.Helper()

	registry, err := keys.NewPublicKeyShareRegistry(
		shares[0].Group(),
		threshold,
		total,
		shares[0].VerificationKey(),
		publicShares(shares),
	)
	if err != nil {
		t.Fatal(err)
	}

	return registry
}

func requireError(t *testing.T, err error) {
	t.Helper()

	if err == nil {
		t.Fatal("expected an error")
	}
}

func TestCompactDecodeInferredAndPinnedModes(t *testing.T) {
	group := ecc.Ristretto255Sha512
	other := ecc.Edwards25519Sha512
	shares := mustShares(t, group, 2, 3, 42)
	registry := mustRegistry(t, shares, 2, 3)

	publicEncoding := shares[0].PublicKeyShare().Encode()
	if err := new(keys.PublicKeyShare).Decode(publicEncoding); err != nil {
		t.Fatal(err)
	}
	if err := keys.NewPublicKeyShareReceiver(group).Decode(publicEncoding); err != nil {
		t.Fatal(err)
	}
	requireError(t, keys.NewPublicKeyShareReceiver(other).Decode(publicEncoding))

	keyEncoding := shares[0].Encode()
	if err := new(keys.KeyShare).Decode(keyEncoding); err != nil {
		t.Fatal(err)
	}
	if err := keys.NewKeyShareReceiver(group).Decode(keyEncoding); err != nil {
		t.Fatal(err)
	}
	requireError(t, keys.NewKeyShareReceiver(other).Decode(keyEncoding))

	registryEncoding := registry.Encode()
	if err := new(keys.PublicKeyShareRegistry).Decode(registryEncoding); err != nil {
		t.Fatal(err)
	}
	if err := keys.NewPublicKeyShareRegistryReceiver(group).Decode(registryEncoding); err != nil {
		t.Fatal(err)
	}
	requireError(t, keys.NewPublicKeyShareRegistryReceiver(other).Decode(registryEncoding))
}

func TestCompactRegistryRejectsMixedGroupsAndNonCanonicalOrder(t *testing.T) {
	group := ecc.Ristretto255Sha512
	other := ecc.Edwards25519Sha512

	shares := mustShares(t, group, 2, 3, 42)
	registry := mustRegistry(t, shares, 2, 3)
	canonical := registry.Encode()

	for range 32 {
		if encoding := registry.Encode(); !bytes.Equal(encoding, canonical) {
			t.Fatal("registry encoding is not deterministic")
		}
	}

	reversed := []*keys.PublicKeyShare{shares[2].PublicKeyShare(), shares[1].PublicKeyShare(), shares[0].PublicKeyShare()}
	reversedRegistry, err := keys.NewPublicKeyShareRegistry(
		group,
		2,
		3,
		shares[0].VerificationKey(),
		reversed,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reversedRegistry.Encode(), canonical) {
		t.Fatal("registry encoding depends on construction order")
	}

	nonCanonical := bytes.Clone(canonical)
	offset := compactHeaderLength + group.ElementLength()
	shareLength := len(shares[0].PublicKeyShare().Encode())
	first := bytes.Clone(nonCanonical[offset : offset+shareLength])
	copy(nonCanonical[offset:offset+shareLength], nonCanonical[offset+shareLength:offset+2*shareLength])
	copy(nonCanonical[offset+shareLength:offset+2*shareLength], first)
	requireError(t, new(keys.PublicKeyShareRegistry).Decode(nonCanonical))

	oneShare := mustShares(t, group, 1, 1, 42)
	foreignShare := mustShares(t, other, 1, 1, 42)
	mixed := mustRegistry(t, oneShare, 1, 1).Encode()
	mixedOffset := compactHeaderLength + group.ElementLength()
	foreignEncoding := foreignShare[0].PublicKeyShare().Encode()
	if len(foreignEncoding) != len(mixed[mixedOffset:]) {
		t.Fatal("test groups no longer have matching compact public share lengths")
	}
	copy(mixed[mixedOffset:], foreignEncoding)
	requireError(t, new(keys.PublicKeyShareRegistry).Decode(mixed))
}

func TestRegistryConstructionRejectsInvalidState(t *testing.T) {
	group := ecc.Ristretto255Sha512
	shares := mustShares(t, group, 2, 2, 42)

	foreign := mustShares(t, ecc.Edwards25519Sha512, 2, 2, 42)
	differentPolynomial := mustShares(t, group, 2, 2, 43)
	_, err := keys.NewPublicKeyShareRegistry(group, 2, 2, shares[0].VerificationKey(), []*keys.PublicKeyShare{
		nil,
		shares[1].PublicKeyShare(),
	})
	requireError(t, err)
	_, err = keys.NewPublicKeyShareRegistry(group, 2, 2, shares[0].VerificationKey(), []*keys.PublicKeyShare{
		shares[0].PublicKeyShare(),
		shares[0].PublicKeyShare(),
	})
	requireError(t, err)
	_, err = keys.NewPublicKeyShareRegistry(group, 2, 2, shares[0].VerificationKey(), []*keys.PublicKeyShare{
		foreign[0].PublicKeyShare(),
		foreign[1].PublicKeyShare(),
	})
	requireError(t, err)
	_, err = keys.NewPublicKeyShareRegistry(group, 2, 2, shares[0].VerificationKey(), []*keys.PublicKeyShare{
		shares[0].PublicKeyShare(),
		differentPolynomial[1].PublicKeyShare(),
	})
	requireError(t, err)
	_, err = keys.NewPublicKeyShareRegistry(group, 2, 2, differentPolynomial[0].VerificationKey(), publicShares(shares))
	requireError(t, err)

	outOfRangeCommitment := shares[0].PublicKeyShare().Commitment()
	outOfRangePublicKey, err := secretsharing.PubKeyForCommitment(group, 3, outOfRangeCommitment)
	if err != nil {
		t.Fatal(err)
	}
	outOfRange, err := keys.NewPublicKeyShare(group, 3, outOfRangePublicKey, outOfRangeCommitment)
	if err != nil {
		t.Fatal(err)
	}
	_, err = keys.NewPublicKeyShareRegistry(group, 2, 2, shares[0].VerificationKey(), []*keys.PublicKeyShare{
		shares[0].PublicKeyShare(),
		outOfRange,
	})
	requireError(t, err)
}

func TestCompactRegistryDecodeRejectsInvalidSemantics(t *testing.T) {
	group := ecc.Ristretto255Sha512
	shares := mustShares(t, group, 2, 2, 42)
	registry := mustRegistry(t, shares, 2, 2)
	encoding := registry.Encode()
	shareOffset := compactHeaderLength + group.ElementLength()

	zeroThreshold := bytes.Clone(encoding)
	binary.LittleEndian.PutUint16(zeroThreshold[3:5], 0)
	requireError(t, new(keys.PublicKeyShareRegistry).Decode(zeroThreshold))

	zeroTotal := bytes.Clone(encoding)
	binary.LittleEndian.PutUint16(zeroTotal[1:3], 0)
	requireError(t, new(keys.PublicKeyShareRegistry).Decode(zeroTotal))

	thresholdAboveTotal := bytes.Clone(encoding)
	binary.LittleEndian.PutUint16(thresholdAboveTotal[3:5], 3)
	requireError(t, new(keys.PublicKeyShareRegistry).Decode(thresholdAboveTotal))

	outOfRangeID := bytes.Clone(encoding)
	binary.LittleEndian.PutUint16(outOfRangeID[shareOffset+1:shareOffset+3], 3)
	requireError(t, new(keys.PublicKeyShareRegistry).Decode(outOfRangeID))

	wrongCommitmentLength := bytes.Clone(encoding)
	binary.LittleEndian.PutUint16(wrongCommitmentLength[shareOffset+3:shareOffset+5], 1)
	requireError(t, new(keys.PublicKeyShareRegistry).Decode(wrongCommitmentLength))

	duplicateID := bytes.Clone(encoding)
	shareLength := len(shares[0].PublicKeyShare().Encode())
	binary.LittleEndian.PutUint16(duplicateID[shareOffset+shareLength+1:shareOffset+shareLength+3], 1)
	requireError(t, new(keys.PublicKeyShareRegistry).Decode(duplicateID))

	invalidVSS := bytes.Clone(encoding)
	copy(invalidVSS[shareOffset+compactHeaderLength:], group.NewElement().Encode())
	requireError(t, new(keys.PublicKeyShareRegistry).Decode(invalidVSS))

	differentShares := mustShares(t, group, 2, 2, 43)
	wrongVerificationKey := bytes.Clone(encoding)
	copy(wrongVerificationKey[compactHeaderLength:], differentShares[0].VerificationKey().Encode())
	requireError(t, new(keys.PublicKeyShareRegistry).Decode(wrongVerificationKey))
}

func TestRegistryRejectsDivergentCommitmentVectors(t *testing.T) {
	group := ecc.Ristretto255Sha512
	shares := mustSharesWithCoefficient(t, group, 42, 7)
	divergent := mustSharesWithCoefficient(t, group, 42, 8)

	if !shares[0].PublicKeyShare().Commitment()[0].Equal(divergent[0].PublicKeyShare().Commitment()[0]) {
		t.Fatal("test vectors do not share a verification key")
	}
	if shares[0].PublicKeyShare().Commitment()[1].Equal(divergent[0].PublicKeyShare().Commitment()[1]) {
		t.Fatal("test vectors do not diverge after the constant commitment")
	}
	if _, err := keys.NewPublicKeyShareRegistry(
		group,
		2,
		2,
		shares[0].VerificationKey(),
		[]*keys.PublicKeyShare{shares[0].PublicKeyShare(), divergent[1].PublicKeyShare()},
	); err == nil {
		t.Fatal("validated registry constructor accepted divergent commitment vectors")
	}

	compact := mustRegistry(t, shares, 2, 2).Encode()
	shareOffset := compactHeaderLength + group.ElementLength()
	shareLength := len(shares[0].PublicKeyShare().Encode())
	copy(compact[shareOffset+shareLength:], divergent[1].PublicKeyShare().Encode())
	requireError(t, new(keys.PublicKeyShareRegistry).Decode(compact))

	document := mustJSONDocument(t, mustRegistry(t, shares, 2, 2))
	document["publicKeyShares"].(map[string]any)["2"] = mustJSONValue(t, divergent[1].PublicKeyShare())
	requireJSONRegistryError(t, document)
}

func mustJSONDocument(t *testing.T, value any) map[string]any {
	t.Helper()

	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}

	var document map[string]any
	if err = json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}

	return document
}

func mustJSONValue(t *testing.T, value any) any {
	t.Helper()

	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}

	var decoded any
	if err = json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}

	return decoded
}

func requireJSONRegistryError(t *testing.T, document map[string]any) {
	t.Helper()

	data, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}

	requireError(t, json.Unmarshal(data, new(keys.PublicKeyShareRegistry)))
}

func TestRegistryJSONAndCompactRejectEquivalentInvalidState(t *testing.T) {
	group := ecc.Ristretto255Sha512
	shares := mustShares(t, group, 2, 2, 42)
	registry := mustRegistry(t, shares, 2, 2)
	encoding := registry.Encode()
	shareOffset := compactHeaderLength + group.ElementLength()
	differentShares := mustShares(t, group, 2, 2, 43)

	tests := []struct {
		mutateCompact func([]byte)
		mutateJSON    func(map[string]any)
		name          string
	}{
		{
			name: "zero threshold",
			mutateCompact: func(data []byte) {
				binary.LittleEndian.PutUint16(data[3:5], 0)
			},
			mutateJSON: func(document map[string]any) {
				document["threshold"] = float64(0)
			},
		},
		{
			name: "out of range identifier",
			mutateCompact: func(data []byte) {
				binary.LittleEndian.PutUint16(data[shareOffset+1:shareOffset+3], 3)
			},
			mutateJSON: func(document map[string]any) {
				publicShares := document["publicKeyShares"].(map[string]any)
				share := publicShares["1"].(map[string]any)
				delete(publicShares, "1")
				share["id"] = float64(3)
				publicShares["3"] = share
			},
		},
		{
			name: "wrong commitment length",
			mutateCompact: func(data []byte) {
				binary.LittleEndian.PutUint16(data[shareOffset+3:shareOffset+5], 1)
			},
			mutateJSON: func(document map[string]any) {
				share := document["publicKeyShares"].(map[string]any)["1"].(map[string]any)
				share["vssCommitment"] = share["vssCommitment"].([]any)[:1]
			},
		},
		{
			name: "invalid VSS share",
			mutateCompact: func(data []byte) {
				copy(data[shareOffset+compactHeaderLength:], group.NewElement().Encode())
			},
			mutateJSON: func(document map[string]any) {
				share := document["publicKeyShares"].(map[string]any)["1"].(map[string]any)
				share["publicKey"] = mustJSONValue(t, group.NewElement())
			},
		},
		{
			name: "verification key mismatch",
			mutateCompact: func(data []byte) {
				copy(data[compactHeaderLength:], differentShares[0].VerificationKey().Encode())
			},
			mutateJSON: func(document map[string]any) {
				document["verificationKey"] = mustJSONValue(t, differentShares[0].VerificationKey())
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			compact := bytes.Clone(encoding)
			test.mutateCompact(compact)
			requireError(t, new(keys.PublicKeyShareRegistry).Decode(compact))

			document := mustJSONDocument(t, registry)
			test.mutateJSON(document)
			requireJSONRegistryError(t, document)
		})
	}
}

func TestJSONDecodeRejectsNullKeyMaterial(t *testing.T) {
	group := ecc.Ristretto255Sha512
	shares := mustShares(t, group, 2, 2, 42)

	data, err := json.Marshal(shares[0].PublicKeyShare())
	if err != nil {
		t.Fatal(err)
	}

	var document map[string]any
	if err = json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}

	document["publicKey"] = nil
	data, err = json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	requireError(t, json.Unmarshal(data, new(keys.PublicKeyShare)))

	data, err = json.Marshal(shares[0].PublicKeyShare())
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	document["vssCommitment"].([]any)[0] = nil
	data, err = json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	requireError(t, json.Unmarshal(data, new(keys.PublicKeyShare)))
}

func TestCompactShareCommitmentLengthUsesUint16Model(t *testing.T) {
	group := ecc.Ristretto255Sha512
	shares := mustShares(t, group, 2, 2, 42)
	encoding := shares[0].PublicKeyShare().Encode()
	if got := binary.LittleEndian.Uint16(encoding[3:5]); got != 2 {
		t.Fatalf("expected commitment length 2, got %d", got)
	}

	oversized := make([]*ecc.Element, math.MaxUint16+1)
	if _, err := keys.NewPublicKeyShare(
		group,
		1,
		group.Base(),
		oversized,
	); err == nil {
		t.Fatal("validated constructor accepted a commitment length above uint16")
	}
}

func TestValidatedConstructorsAndAccessorsUseDefensiveCopies(t *testing.T) {
	group := ecc.Ristretto255Sha512
	shares := mustShares(t, group, 2, 2, 42)
	source := shares[0]

	sourcePublic := source.PublicKeyShare()
	publicKey := sourcePublic.PublicKey()
	commitment := sourcePublic.Commitment()
	public, err := keys.NewPublicKeyShare(group, source.Identifier(), publicKey, commitment)
	if err != nil {
		t.Fatal(err)
	}
	publicKey.Identity()
	commitment[0].Identity()
	if public.PublicKey().IsIdentity() || public.Commitment()[0].IsIdentity() {
		t.Fatal("validated public share retained caller aliases")
	}

	secret := source.SecretKey()
	verificationKey := source.VerificationKey()
	commitment = sourcePublic.Commitment()
	key, err := keys.NewKeyShare(group, source.Identifier(), secret, verificationKey, commitment)
	if err != nil {
		t.Fatal(err)
	}
	secret.Zero()
	verificationKey.Identity()
	commitment[0].Identity()
	if err = key.Validate(); err != nil {
		t.Fatal(err)
	}

	registry := mustRegistry(t, shares, 2, 2)
	copies := registry.Shares()
	copies[0].PublicKey().Identity()
	copies[0].Commitment()[0].Identity()
	if err = registry.Validate(); err != nil {
		t.Fatal(err)
	}

	incoming := source.PublicKeyShare()
	registry, err = keys.NewPublicKeyShareRegistry(
		group,
		2,
		2,
		source.VerificationKey(),
		[]*keys.PublicKeyShare{incoming, shares[1].PublicKeyShare()},
	)
	if err != nil {
		t.Fatal(err)
	}
	incoming.PublicKey().Identity()
	incoming.Commitment()[0].Identity()
	if err = registry.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestRegistryCommitmentReturnsDefensiveCopy(t *testing.T) {
	var nilRegistry *keys.PublicKeyShareRegistry
	if commitment := nilRegistry.Commitment(); commitment != nil {
		t.Fatal("nil registry returned a commitment")
	}

	group := ecc.Ristretto255Sha512
	empty := keys.NewPublicKeyShareRegistryReceiver(group)
	if commitment := empty.Commitment(); commitment != nil {
		t.Fatal("empty registry returned a commitment")
	}

	shares := mustShares(t, group, 2, 2, 42)
	registry := mustRegistry(t, shares, 2, 2)
	commitment := registry.Commitment()
	if len(commitment) != 2 {
		t.Fatalf("expected commitment length 2, got %d", len(commitment))
	}
	for i, element := range commitment {
		if !element.Equal(shares[0].PublicKeyShare().Commitment()[i]) {
			t.Fatalf("commitment element %d differs from the shared registry vector", i)
		}
	}

	commitment[0].Identity()
	commitment[1] = nil
	if err := registry.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestStandaloneShareValidationRejectsInvalidVSSCommitment(t *testing.T) {
	group := ecc.Ristretto255Sha512
	shares := mustShares(t, group, 2, 2, 42)
	source := shares[0]

	public := source.PublicKeyShare()
	commitment := public.Commitment()
	commitment[1].Identity()
	if _, err := keys.NewPublicKeyShare(group, public.Identifier(), public.PublicKey(), commitment); err == nil {
		t.Fatal("validated public share constructor accepted an invalid VSS commitment")
	}

	data, err := json.Marshal(source.PublicKeyShare())
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err = json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	document["vssCommitment"].([]any)[1] = mustJSONValue(t, group.NewElement())
	data, err = json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	requireError(t, json.Unmarshal(data, new(keys.PublicKeyShare)))

	encoded := source.PublicKeyShare().Encode()
	offset := compactHeaderLength + group.ElementLength() + group.ElementLength()
	copy(encoded[offset:offset+group.ElementLength()], group.NewElement().Encode())
	requireError(t, new(keys.PublicKeyShare).Decode(encoded))
}

func TestMalformedECCWrappersFailClosed(t *testing.T) {
	group := ecc.Ristretto255Sha512
	if _, err := keys.NewPublicKeyShare(group, 1, new(ecc.Element), nil); err == nil {
		t.Fatal("validated constructor accepted a malformed ECC element")
	}
}
