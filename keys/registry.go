// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package keys

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/bytemare/ecc"
)

// PublicKeyShareRegistry regroups the final public information about key shares and participants, enabling a registry
// and public key verifications.
type PublicKeyShareRegistry struct {
	VerificationKey *ecc.Element               `json:"verificationKey"`
	PublicKeyShares map[uint16]*PublicKeyShare `json:"publicKeyShares"`
	Total           uint16                     `json:"total"`
	Threshold       uint16                     `json:"threshold"`
	Group           ecc.Group                  `json:"group"`
}

// NewEmptyPublicKeyShareRegistry returns an empty PublicKeyShareRegistry receiver pinned to g for JSON decoding.
// When passed to json.Unmarshal, the encoded top-level group and every encoded public key share and verification key
// must belong to g. Use a zero-value receiver instead when the group should be inferred from self-describing JSON.
func NewEmptyPublicKeyShareRegistry(g ecc.Group) *PublicKeyShareRegistry {
	r := &PublicKeyShareRegistry{
		PublicKeyShares: make(map[uint16]*PublicKeyShare),
		Group:           g,
	}
	if g.Available() {
		r.VerificationKey = g.NewElement()
	}

	return r
}

// NewPublicKeyShareRegistry returns a populated PublicKeyShareRegistry.
func NewPublicKeyShareRegistry(g ecc.Group, threshold, total uint16) *PublicKeyShareRegistry {
	return &PublicKeyShareRegistry{
		Group:           g,
		Threshold:       threshold,
		Total:           total,
		VerificationKey: nil,
		PublicKeyShares: make(map[uint16]*PublicKeyShare, total),
	}
}

// Add adds the PublicKeyShare to the registry if it's not full or no key for the identifier is already set,
// in which case an error is returned.
func (k *PublicKeyShareRegistry) Add(pks *PublicKeyShare) error {
	if _, ok := k.PublicKeyShares[pks.ID]; ok {
		return errPublicKeyShareRegistered
	}

	if len(k.PublicKeyShares) == int(k.Total) {
		return errPublicKeyShareCapacityExceeded
	}

	k.PublicKeyShares[pks.ID] = pks

	return nil
}

// Get returns the registered public key for id, or nil.
func (k *PublicKeyShareRegistry) Get(id uint16) *PublicKeyShare {
	for _, pks := range k.PublicKeyShares {
		if pks != nil && pks.ID == id {
			return pks
		}
	}

	return nil
}

// VerifyPublicKey returns nil if the id / pubKey pair is registered, and an error otherwise.
func (k *PublicKeyShareRegistry) VerifyPublicKey(id uint16, pubKey *ecc.Element) error {
	for _, ks := range k.PublicKeyShares {
		if ks.ID == id {
			if pubKey == nil {
				return errNilPubKey
			}

			if ks.PublicKey == nil {
				return fmt.Errorf("%w for ID %d", errRegistryHasNilPublicKey, id)
			}

			if !ks.PublicKey.Equal(pubKey) {
				return fmt.Errorf("%w for ID %d", errVerifyBadPubKey, id)
			}

			return nil
		}
	}

	return fmt.Errorf("%w: %d", errVerifyUnknownID, id)
}

func registryByteSize(g ecc.Group, threshold, total uint16) (size, pksLen int) {
	eLen := g.ElementLength()
	pksLen = 1 + 2 + 4 + eLen + int(threshold)*eLen

	return 1 + 2 + 2 + g.ElementLength() + int(total)*pksLen, pksLen
}

// Encode serializes the registry into a compact byte encoding of the registry, suitable for storage or transmissions.
func (k *PublicKeyShareRegistry) Encode() []byte {
	size, _ := registryByteSize(k.Group, k.Threshold, k.Total)
	out := make([]byte, 5, size)
	out[0] = byte(k.Group)
	binary.LittleEndian.PutUint16(out[1:3], k.Total)
	binary.LittleEndian.PutUint16(out[3:5], k.Threshold)
	out = append(out, k.VerificationKey.Encode()...)

	for _, pks := range k.PublicKeyShares {
		out = append(out, pks.Encode()...)
	}

	return out
}

// Hex returns the hexadecimal representation of the byte encoding returned by Encode().
func (k *PublicKeyShareRegistry) Hex() string {
	return hex.EncodeToString(k.Encode())
}

// Decode deserializes the input data into the registry, expecting the same encoding as used in Encode(). It doesn't
// modify the receiver when encountering an error.
func (k *PublicKeyShareRegistry) Decode(data []byte) error {
	if len(data) < 5 {
		return fmt.Errorf(errFmt, errRegistryDecodePrefix, errEncodingInvalidLength)
	}

	g := ecc.Group(data[0])
	if !g.Available() {
		return fmt.Errorf(errFmt, errRegistryDecodePrefix, errEncodingInvalidGroup)
	}

	total := binary.LittleEndian.Uint16(data[1:3])
	threshold := binary.LittleEndian.Uint16(data[3:5])
	size, pksLen := registryByteSize(g, threshold, total)

	if len(data) != size {
		return fmt.Errorf(errFmt, errRegistryDecodePrefix, errEncodingInvalidLength)
	}

	eLen := g.ElementLength()

	gpk := g.NewElement()
	if err := gpk.Decode(data[5 : 5+eLen]); err != nil {
		return fmt.Errorf("%w: invalid group public key encoding: %w", errRegistryDecodePrefix, err)
	}

	pks := make(map[uint16]*PublicKeyShare, total)
	offset := 5 + eLen

	for i := range total {
		pk := new(PublicKeyShare)
		if err := pk.Decode(data[offset : offset+pksLen]); err != nil {
			return fmt.Errorf("%w: could not decode public key share %d: %w", errRegistryDecodePrefix, i+1, err)
		}

		if _, ok := pks[pk.ID]; ok {
			return fmt.Errorf(errFmt, errRegistryDecodePrefix, errEncodingPKSDuplication)
		}

		pks[pk.ID] = pk
		offset += pksLen
	}

	k.Group = g
	k.Total = total
	k.Threshold = threshold
	k.VerificationKey = gpk
	k.PublicKeyShares = pks

	return nil
}

// DecodeHex sets k to the decoding of the hex encoded representation returned by Hex().
func (k *PublicKeyShareRegistry) DecodeHex(h string) error {
	b, err := hex.DecodeString(h)
	if err != nil {
		return fmt.Errorf(errFmt, errRegistryDecodePrefix, err)
	}

	return k.Decode(b)
}

// UnmarshalJSON reads the input data as JSON and deserializes it into the receiver. It doesn't modify the receiver when
// encountering an error. If k.Group is zero, the group is inferred from the encoded top-level group. If k.Group is
// non-zero, it must identify an available group and match the encoded top-level group. Every encoded element group must
// match the resolved group.
func (k *PublicKeyShareRegistry) UnmarshalJSON(data []byte) error {
	decoded, err := decodeRegistryJSON(k.Group, data)
	if err != nil {
		return fmt.Errorf(errFmt, errRegistryDecodePrefix, err)
	}

	*k = *decoded

	return nil
}

func decodeRegistryJSON(receiver ecc.Group, data []byte) (*PublicKeyShareRegistry, error) {
	var wire registryJSON
	if err := json.Unmarshal(data, &wire); err != nil {
		return nil, err
	}

	g, err := resolveJSONGroup(receiver, wire.Group)
	if err != nil {
		return nil, err
	}

	if wire.Total == 0 || wire.Threshold == 0 || wire.Threshold > wire.Total {
		return nil, fmt.Errorf("%w: invalid total or threshold", errEncodingInvalidJSONEncoding)
	}

	if len(wire.PublicKeyShares) != int(wire.Total) {
		return nil, fmt.Errorf("%w: public key share count does not match total", errEncodingInvalidJSONEncoding)
	}

	if err := requireJSONField(wire.VerificationKey); err != nil {
		return nil, err
	}

	gpk := g.NewElement()
	if err := json.Unmarshal(wire.VerificationKey, gpk); err != nil {
		return nil, fmt.Errorf("invalid group public key encoding: %w", err)
	}

	pks := make(map[uint16]*PublicKeyShare, wire.Total)
	for id, raw := range wire.PublicKeyShares {
		pk := NewPublicKeyShare(g)
		if err := json.Unmarshal(raw, pk); err != nil {
			return nil, fmt.Errorf("could not decode public key share %d: %w", id, err)
		}

		if pk.ID != id {
			return nil, fmt.Errorf(
				"%w: public key share map key %d does not match share ID %d",
				errEncodingInvalidJSONEncoding,
				id,
				pk.ID,
			)
		}

		if len(pk.VssCommitment) != int(wire.Threshold) {
			return nil, fmt.Errorf(
				"%w: public key share %d commitment length does not match threshold",
				errEncodingInvalidJSONEncoding,
				id,
			)
		}

		if _, ok := pks[pk.ID]; ok {
			return nil, errEncodingPKSDuplication
		}

		pks[pk.ID] = pk
	}

	return &PublicKeyShareRegistry{
		VerificationKey: gpk,
		PublicKeyShares: pks,
		Total:           wire.Total,
		Threshold:       wire.Threshold,
		Group:           g,
	}, nil
}
