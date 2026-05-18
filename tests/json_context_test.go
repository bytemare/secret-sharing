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
	"fmt"
	"strings"
	"testing"

	"github.com/bytemare/ecc"

	"github.com/bytemare/secret-sharing/keys"

	secretsharing "github.com/bytemare/secret-sharing"
)

func otherAvailableGroup(g ecc.Group) ecc.Group {
	if g == ecc.Ristretto255Sha512 {
		return ecc.P256Sha256
	}

	return ecc.Ristretto255Sha512
}

func mustMarshalJSON(t testing.TB, in any) []byte {
	t.Helper()

	out, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}

	return out
}

func mutateJSONObject(t testing.TB, data []byte, f func(map[string]any)) []byte {
	t.Helper()

	var document map[string]any
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}

	f(document)

	return mustMarshalJSON(t, document)
}

func expectJSONUnmarshalError(t testing.TB, receiver json.Unmarshaler, data []byte, expectedPrefix string) {
	t.Helper()

	err := json.Unmarshal(data, receiver)
	if err == nil || !strings.HasPrefix(err.Error(), expectedPrefix) {
		t.Fatalf("expected error prefix %q, got %q", expectedPrefix, err)
	}
}

func makeJSONTestMaterial(
	t testing.TB,
	g ecc.Group,
	threshold, total uint16,
) ([]*keys.KeyShare, *keys.PublicKeyShareRegistry) {
	t.Helper()

	secret := g.NewScalar().SetUInt64(uint64(threshold) + uint64(total))
	shares, err := secretsharing.ShardAndCommit(g, secret, threshold, total)
	if err != nil {
		t.Fatal(err)
	}

	registry := keys.NewPublicKeyShareRegistry(g, threshold, total)
	for _, share := range shares {
		if err = registry.Add(share.Public()); err != nil {
			t.Fatal(err)
		}
	}
	registry.VerificationKey = shares[0].VerificationKey

	return shares, registry
}

// TestPublicKeyShareJSONDecode_Table verifies PublicKeyShare JSON decoding failures.
func TestPublicKeyShareJSONDecode_Table(t *testing.T) {
	for _, g := range groups {
		t.Run(g.String(), func(t *testing.T) {
			shares, _ := makeJSONTestMaterial(t, g, 3, 4)
			source := shares[0].Public()
			data := mustMarshalJSON(t, source)
			other := otherAvailableGroup(g)

			tests := []struct {
				recv     *keys.PublicKeyShare
				name     string
				wantPref string
				data     []byte
			}{
				{
					name:     "invalid nonzero receiver group",
					recv:     &keys.PublicKeyShare{Group: ecc.Group(255)},
					data:     data,
					wantPref: "failed to decode PublicKeyShare: invalid group identifier",
				},
				{
					name:     "wrong receiver group",
					recv:     keys.NewPublicKeyShare(other),
					data:     data,
					wantPref: "failed to decode PublicKeyShare: encoded group does not match receiver group",
				},
				{
					name: "invalid top-level group",
					recv: keys.NewPublicKeyShare(g),
					data: mutateJSONObject(t, data, func(document map[string]any) {
						document["group"] = 0
					}),
					wantPref: "failed to decode PublicKeyShare: invalid group identifier",
				},
				{
					name: "missing top-level group",
					recv: new(keys.PublicKeyShare),
					data: mutateJSONObject(t, data, func(document map[string]any) {
						delete(document, "group")
					}),
					wantPref: "failed to decode PublicKeyShare: invalid group identifier",
				},
				{
					name: "public key group mismatch",
					recv: new(keys.PublicKeyShare),
					data: mutateJSONObject(t, data, func(document map[string]any) {
						publicKey := document["publicKey"].(map[string]any)
						publicKey["group"] = float64(other)
					}),
					wantPref: "failed to decode PublicKeyShare: failed to decode public key",
				},
				{
					name: "commitment is not an array",
					recv: keys.NewPublicKeyShare(g),
					data: mutateJSONObject(t, data, func(document map[string]any) {
						document["vssCommitment"] = "nope"
					}),
					wantPref: "failed to decode PublicKeyShare: json: cannot unmarshal string",
				},
			}

			for _, test := range tests {
				t.Run(test.name, func(t *testing.T) {
					expectJSONUnmarshalError(t, test.recv, test.data, test.wantPref)
				})
			}
		})
	}
}

// TestKeyShareJSONDecode_Table verifies KeyShare JSON decoding failures.
func TestKeyShareJSONDecode_Table(t *testing.T) {
	for _, g := range groups {
		t.Run(g.String(), func(t *testing.T) {
			shares, _ := makeJSONTestMaterial(t, g, 2, 3)
			source := shares[0]
			data := mustMarshalJSON(t, source)
			other := otherAvailableGroup(g)

			tests := []struct {
				recv     *keys.KeyShare
				name     string
				wantPref string
				data     []byte
			}{
				{
					name:     "invalid nonzero receiver group",
					recv:     &keys.KeyShare{PublicKeyShare: keys.PublicKeyShare{Group: ecc.Group(255)}},
					data:     data,
					wantPref: "failed to decode KeyShare: failed to decode PublicKeyShare: invalid group identifier",
				},
				{
					name:     "wrong receiver group",
					recv:     keys.NewKeyShare(other),
					data:     data,
					wantPref: "failed to decode KeyShare: failed to decode PublicKeyShare: encoded group does not match receiver group",
				},
				{
					name: "missing top-level group",
					recv: new(keys.KeyShare),
					data: mutateJSONObject(t, data, func(document map[string]any) {
						delete(document, "group")
					}),
					wantPref: "failed to decode KeyShare: failed to decode PublicKeyShare: invalid group identifier",
				},
				{
					name: "invalid top-level group",
					recv: new(keys.KeyShare),
					data: mutateJSONObject(t, data, func(document map[string]any) {
						document["group"] = 0
					}),
					wantPref: "failed to decode KeyShare: failed to decode PublicKeyShare: invalid group identifier",
				},
				{
					name: "secret group mismatch",
					recv: new(keys.KeyShare),
					data: mutateJSONObject(t, data, func(document map[string]any) {
						secret := document["secret"].(map[string]any)
						secret["group"] = float64(other)
					}),
					wantPref: "failed to decode KeyShare: failed to decode secret key",
				},
				{
					name: "verification key group mismatch",
					recv: new(keys.KeyShare),
					data: mutateJSONObject(t, data, func(document map[string]any) {
						verificationKey := document["verificationKey"].(map[string]any)
						verificationKey["group"] = float64(other)
					}),
					wantPref: "failed to decode KeyShare: failed to decode VerificationKey",
				},
			}

			for _, test := range tests {
				t.Run(test.name, func(t *testing.T) {
					expectJSONUnmarshalError(t, test.recv, test.data, test.wantPref)
				})
			}
		})
	}
}

// TestRegistryJSONDecode_Table verifies registry JSON decoding failures and registry invariants.
func TestRegistryJSONDecode_Table(t *testing.T) {
	for _, g := range groups {
		t.Run(g.String(), func(t *testing.T) {
			_, registry := makeJSONTestMaterial(t, g, 2, 3)
			data := mustMarshalJSON(t, registry)
			other := otherAvailableGroup(g)

			tests := []struct {
				recv     *keys.PublicKeyShareRegistry
				name     string
				wantPref string
				data     []byte
			}{
				{
					name:     "invalid nonzero receiver group",
					recv:     &keys.PublicKeyShareRegistry{Group: ecc.Group(255)},
					data:     data,
					wantPref: "failed to decode PublicKeyShareRegistry: invalid group identifier",
				},
				{
					name:     "wrong receiver group",
					recv:     keys.NewEmptyPublicKeyShareRegistry(other),
					data:     data,
					wantPref: "failed to decode PublicKeyShareRegistry: encoded group does not match receiver group",
				},
				{
					name: "missing top-level group",
					recv: new(keys.PublicKeyShareRegistry),
					data: mutateJSONObject(t, data, func(document map[string]any) {
						delete(document, "group")
					}),
					wantPref: "failed to decode PublicKeyShareRegistry: invalid group identifier",
				},
				{
					name: "invalid top-level group",
					recv: new(keys.PublicKeyShareRegistry),
					data: mutateJSONObject(t, data, func(document map[string]any) {
						document["group"] = 0
					}),
					wantPref: "failed to decode PublicKeyShareRegistry: invalid group identifier",
				},
				{
					name: "share count mismatch",
					recv: keys.NewEmptyPublicKeyShareRegistry(g),
					data: mutateJSONObject(t, data, func(document map[string]any) {
						document["total"] = 4
					}),
					wantPref: "failed to decode PublicKeyShareRegistry: invalid JSON encoding: public key share count does not match total",
				},
				{
					name: "map key share id mismatch",
					recv: keys.NewEmptyPublicKeyShareRegistry(g),
					data: mutateJSONObject(t, data, func(document map[string]any) {
						shares := document["publicKeyShares"].(map[string]any)
						share := shares["1"].(map[string]any)
						share["id"] = 2
					}),
					wantPref: "failed to decode PublicKeyShareRegistry: invalid JSON encoding: public key share map key 1 does not match share ID 2",
				},
				{
					name: "commitment length mismatch",
					recv: keys.NewEmptyPublicKeyShareRegistry(g),
					data: mutateJSONObject(t, data, func(document map[string]any) {
						shares := document["publicKeyShares"].(map[string]any)
						share := shares["1"].(map[string]any)
						share["vssCommitment"] = []any{}
					}),
					wantPref: "failed to decode PublicKeyShareRegistry: invalid JSON encoding: public key share 1 commitment length does not match threshold",
				},
				{
					name: "verification key group mismatch",
					recv: new(keys.PublicKeyShareRegistry),
					data: mutateJSONObject(t, data, func(document map[string]any) {
						verificationKey := document["verificationKey"].(map[string]any)
						verificationKey["group"] = float64(other)
					}),
					wantPref: "failed to decode PublicKeyShareRegistry: invalid group public key encoding",
				},
			}

			for _, test := range tests {
				t.Run(test.name, func(t *testing.T) {
					expectJSONUnmarshalError(t, test.recv, test.data, test.wantPref)
				})
			}
		})
	}
}

// TestJSONRoundTripProperties checks JSON roundtrip properties across groups and threshold settings.
func TestJSONRoundTripProperties(t *testing.T) {
	params := []struct {
		threshold uint16
		total     uint16
	}{
		{threshold: 1, total: 2},
		{threshold: 2, total: 3},
		{threshold: 3, total: 5},
	}

	for _, g := range groups {
		for _, param := range params {
			name := fmt.Sprintf("%s/%d-of-%d", g, param.threshold, param.total)
			t.Run(name, func(t *testing.T) {
				shares, registry := makeJSONTestMaterial(t, g, param.threshold, param.total)

				decodedShares := make([]*keys.KeyShare, len(shares))
				for i, share := range shares {
					data := mustMarshalJSON(t, share)
					inferred := new(keys.KeyShare)

					if err := json.Unmarshal(data, inferred); err != nil {
						t.Fatal(err)
					}

					if err := compareKeyShares(share, inferred, true); err != nil {
						t.Fatal(err)
					}

					pinned := keys.NewKeyShare(g)
					if err := json.Unmarshal(data, pinned); err != nil {
						t.Fatal(err)
					}

					if err := compareKeyShares(share, pinned, true); err != nil {
						t.Fatal(err)
					}

					publicData := mustMarshalJSON(t, share.Public())
					inferredPublic := new(keys.PublicKeyShare)
					if err := json.Unmarshal(publicData, inferredPublic); err != nil {
						t.Fatal(err)
					}
					if err := comparePublicKeyShare(share.Public(), inferredPublic, true); err != nil {
						t.Fatal(err)
					}

					pinnedPublic := keys.NewPublicKeyShare(g)
					if err := json.Unmarshal(publicData, pinnedPublic); err != nil {
						t.Fatal(err)
					}
					if err := comparePublicKeyShare(share.Public(), pinnedPublic, true); err != nil {
						t.Fatal(err)
					}

					if !secretsharing.VerifyPublicKeyShare(inferred.Public()) {
						t.Fatalf("decoded public key share %d does not verify", inferred.ID)
					}

					decodedShares[i] = inferred
				}

				recovered, err := secretsharing.CombineShares(decodedShares[:param.threshold])
				if err != nil {
					t.Fatal(err)
				}

				expected, err := secretsharing.CombineShares(shares[:param.threshold])
				if err != nil {
					t.Fatal(err)
				}

				if !recovered.Equal(expected) {
					t.Fatal("decoded shares did not recover the same secret")
				}

				data := mustMarshalJSON(t, registry)
				inferredRegistry := new(keys.PublicKeyShareRegistry)

				if err = json.Unmarshal(data, inferredRegistry); err != nil {
					t.Fatal(err)
				}

				if err = compareRegistries(registry, inferredRegistry); err != nil {
					t.Fatal(err)
				}

				pinnedRegistry := keys.NewEmptyPublicKeyShareRegistry(g)
				if err = json.Unmarshal(data, pinnedRegistry); err != nil {
					t.Fatal(err)
				}

				if err = compareRegistries(registry, pinnedRegistry); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

// TestJSONDecodeRejectsLegacyECCValues verifies that nested ECC values must use the current object encoding.
func TestJSONDecodeRejectsLegacyECCValues(t *testing.T) {
	for _, g := range groups {
		t.Run(g.String(), func(t *testing.T) {
			shares, registry := makeJSONTestMaterial(t, g, 2, 3)

			publicData := mustMarshalJSON(t, shares[0].Public())
			publicData = mutateJSONObject(t, publicData, func(document map[string]any) {
				publicKey := document["publicKey"].(map[string]any)
				document["publicKey"] = publicKey["data"]
			})
			expectJSONUnmarshalError(
				t,
				new(keys.PublicKeyShare),
				publicData,
				"failed to decode PublicKeyShare: failed to decode public key",
			)

			keyData := mustMarshalJSON(t, shares[0])
			keyData = mutateJSONObject(t, keyData, func(document map[string]any) {
				secret := document["secret"].(map[string]any)
				document["secret"] = secret["data"]
			})
			expectJSONUnmarshalError(
				t,
				new(keys.KeyShare),
				keyData,
				"failed to decode KeyShare: failed to decode secret key",
			)

			registryData := mustMarshalJSON(t, registry)
			registryData = mutateJSONObject(t, registryData, func(document map[string]any) {
				verificationKey := document["verificationKey"].(map[string]any)
				document["verificationKey"] = verificationKey["data"]
			})
			expectJSONUnmarshalError(
				t,
				new(keys.PublicKeyShareRegistry),
				registryData,
				"failed to decode PublicKeyShareRegistry: invalid group public key encoding",
			)
		})
	}
}
