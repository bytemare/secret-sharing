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
	verificationKey *ecc.Element
	publicKeyShares map[uint16]*PublicKeyShare
	total           uint16
	threshold       uint16
	group           ecc.Group
}

// NewPublicKeyShareRegistryReceiver returns a PublicKeyShareRegistry receiver pinned to g for JSON and compact
// decoding. Use a zero-value receiver instead when the group should be inferred from self-describing input.
func NewPublicKeyShareRegistryReceiver(g ecc.Group) *PublicKeyShareRegistry {
	r := &PublicKeyShareRegistry{
		publicKeyShares: make(map[uint16]*PublicKeyShare),
		group:           g,
	}
	if g.Available() {
		r.verificationKey = g.NewElement()
	}

	return r
}

// NewPublicKeyShareRegistry returns a complete valid registry with defensive copies of the caller's key material.
func NewPublicKeyShareRegistry(
	g ecc.Group,
	threshold, total uint16,
	verificationKey *ecc.Element,
	shares []*PublicKeyShare,
) (*PublicKeyShareRegistry, error) {
	registry := &PublicKeyShareRegistry{
		verificationKey: cloneElement(verificationKey),
		publicKeyShares: make(map[uint16]*PublicKeyShare, len(shares)),
		total:           total,
		threshold:       threshold,
		group:           g,
	}

	for _, share := range shares {
		if err := validatePublicKeyShare(share); err != nil {
			return nil, err
		}

		if _, ok := registry.publicKeyShares[share.id]; ok {
			return nil, errPublicKeyShareRegistered
		}

		registry.publicKeyShares[share.id] = clonePublicKeyShare(share)
	}

	if err := registry.Validate(); err != nil {
		return nil, err
	}

	return registry, nil
}

// Group returns the elliptic curve group used for this registry.
func (k *PublicKeyShareRegistry) Group() ecc.Group {
	if k == nil {
		return 0
	}

	return k.group
}

// Threshold returns the minimum number of shares required for reconstruction.
func (k *PublicKeyShareRegistry) Threshold() uint16 {
	if k == nil {
		return 0
	}

	return k.threshold
}

// Total returns the number of shares in a complete registry.
func (k *PublicKeyShareRegistry) Total() uint16 {
	if k == nil {
		return 0
	}

	return k.total
}

// VerificationKey returns a defensive copy of the group verification key.
func (k *PublicKeyShareRegistry) VerificationKey() *ecc.Element {
	if k == nil {
		return nil
	}

	return cloneElement(k.verificationKey)
}

// Shares returns defensive copies of the registered shares ordered by identifier.
func (k *PublicKeyShareRegistry) Shares() []*PublicKeyShare {
	if k == nil {
		return nil
	}

	shares := make([]*PublicKeyShare, 0, len(k.publicKeyShares))
	for _, id := range sortedShareIDs(k.publicKeyShares) {
		shares = append(shares, clonePublicKeyShare(k.publicKeyShares[id]))
	}

	return shares
}

// Commitment returns a defensive copy of the complete registry's shared VSS commitment.
func (k *PublicKeyShareRegistry) Commitment() []*ecc.Element {
	if k == nil || len(k.publicKeyShares) == 0 {
		return nil
	}

	if err := k.Validate(); err != nil {
		return nil
	}

	for _, id := range sortedShareIDs(k.publicKeyShares) {
		return k.publicKeyShares[id].Commitment()
	}

	return nil
}

// Validate returns an error unless k is a complete registry satisfying the registry invariants.
func (k *PublicKeyShareRegistry) Validate() error {
	return validateRegistry(k, true)
}

// Get returns a defensive copy of the registered public key for id, or nil.
func (k *PublicKeyShareRegistry) Get(id uint16) *PublicKeyShare {
	if k == nil {
		return nil
	}

	return clonePublicKeyShare(k.publicKeyShares[id])
}

// ContainsPublicKey returns nil if the id / pubKey pair is registered, and an error otherwise.
func (k *PublicKeyShareRegistry) ContainsPublicKey(id uint16, pubKey *ecc.Element) error {
	if k == nil {
		return errNilRegistry
	}

	if pubKey == nil {
		return errNilPubKey
	}

	share := k.publicKeyShares[id]
	if share == nil {
		return fmt.Errorf("%w: %d", errVerifyUnknownID, id)
	}

	if share.publicKey == nil {
		return fmt.Errorf("%w for ID %d", errRegistryHasNilPublicKey, id)
	}

	if err := k.Validate(); err != nil {
		return fmt.Errorf("%w: %w", errInvalidRegistry, err)
	}

	pubKeyGroup, ok := elementGroup(pubKey)
	if !ok || pubKeyGroup != k.group || !share.publicKey.Equal(pubKey) {
		return fmt.Errorf("%w for ID %d", errVerifyBadPubKey, id)
	}

	return nil
}

func registryByteSize(g ecc.Group, threshold, total uint16) (size, pksLen int) {
	pksLen = publicKeyShareLength(g, int(threshold))

	return sharedHeaderLength + g.ElementLength() + int(total)*pksLen, pksLen
}

// Encode serializes the registry into a compact byte encoding of the registry, suitable for storage or transmissions.
func (k *PublicKeyShareRegistry) Encode() []byte {
	if err := k.Validate(); err != nil {
		return nil
	}

	size, _ := registryByteSize(k.group, k.threshold, k.total)
	out := make([]byte, sharedHeaderLength, size)
	out[0] = byte(k.group)
	binary.LittleEndian.PutUint16(out[1:3], k.total)
	binary.LittleEndian.PutUint16(out[3:5], k.threshold)
	out = append(out, k.verificationKey.Encode()...)

	for _, id := range sortedShareIDs(k.publicKeyShares) {
		out = append(out, k.publicKeyShares[id].Encode()...)
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
	if k == nil {
		return fmt.Errorf(errFmt, errRegistryDecodePrefix, errNilRegistry)
	}

	if len(data) < sharedHeaderLength {
		return fmt.Errorf(errFmt, errRegistryDecodePrefix, errEncodingInvalidLength)
	}

	g, err := resolveDecodedGroup(k.group, ecc.Group(data[0]))
	if err != nil {
		return fmt.Errorf(errFmt, errRegistryDecodePrefix, err)
	}

	total := binary.LittleEndian.Uint16(data[1:3])
	threshold := binary.LittleEndian.Uint16(data[3:5])

	if err = validateRegistryParameters(g, threshold, total); err != nil {
		return fmt.Errorf(errFmt, errRegistryDecodePrefix, err)
	}

	size, pksLen := registryByteSize(g, threshold, total)
	if len(data) != size {
		return fmt.Errorf(errFmt, errRegistryDecodePrefix, errEncodingInvalidLength)
	}

	eLen := g.ElementLength()

	gpk := g.NewElement()
	if err = gpk.Decode(data[sharedHeaderLength : sharedHeaderLength+eLen]); err != nil {
		return fmt.Errorf("%w: invalid group public key encoding: %w", errRegistryDecodePrefix, err)
	}

	pks := make(map[uint16]*PublicKeyShare, total)
	offset := sharedHeaderLength + eLen

	var previousID uint16

	for i := range total {
		pk := newPublicKeyShareReceiver(g)
		if err = pk.Decode(data[offset : offset+pksLen]); err != nil {
			return fmt.Errorf("%w: could not decode public key share %d: %w", errRegistryDecodePrefix, i+1, err)
		}

		if _, ok := pks[pk.id]; ok {
			return fmt.Errorf(errFmt, errRegistryDecodePrefix, errEncodingPKSDuplication)
		}

		if i != 0 && pk.id <= previousID {
			return fmt.Errorf(errFmt, errRegistryDecodePrefix, errEncodingNonCanonicalPublicKeyShareOrder)
		}

		pks[pk.id] = pk
		previousID = pk.id
		offset += pksLen
	}

	registry := &PublicKeyShareRegistry{
		verificationKey: gpk,
		publicKeyShares: pks,
		total:           total,
		threshold:       threshold,
		group:           g,
	}
	if err = registry.Validate(); err != nil {
		return fmt.Errorf(errFmt, errRegistryDecodePrefix, err)
	}

	*k = *registry

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

// MarshalJSON encodes k using the stable public wire contract.
func (k *PublicKeyShareRegistry) MarshalJSON() ([]byte, error) {
	if err := k.Validate(); err != nil {
		return nil, err
	}

	encoded, err := json.Marshal(struct {
		VerificationKey *ecc.Element               `json:"verificationKey"`
		PublicKeyShares map[uint16]*PublicKeyShare `json:"publicKeyShares"`
		Total           uint16                     `json:"total"`
		Threshold       uint16                     `json:"threshold"`
		Group           ecc.Group                  `json:"group"`
	}{
		VerificationKey: k.verificationKey,
		PublicKeyShares: k.publicKeyShares,
		Total:           k.total,
		Threshold:       k.threshold,
		Group:           k.group,
	})
	if err != nil {
		return nil, fmt.Errorf("json marshalling PublicKeyShareRegistry: %w", err)
	}

	return encoded, nil
}

// UnmarshalJSON reads the input data as JSON and deserializes it into the receiver. It doesn't modify the receiver when
// encountering an error. If k.Group() is zero, the group is inferred from the encoded top-level group. If k.Group() is
// non-zero, it must identify an available group and match the encoded top-level group. Every encoded element group must
// match the resolved group.
func (k *PublicKeyShareRegistry) UnmarshalJSON(data []byte) error {
	if k == nil {
		return fmt.Errorf(errFmt, errRegistryDecodePrefix, errNilRegistry)
	}

	decoded, err := decodeRegistryJSON(k.group, data)
	if err != nil {
		return err
	}

	*k = *decoded

	return nil
}

func decodeRegistryJSON(receiver ecc.Group, data []byte) (*PublicKeyShareRegistry, error) {
	var wire registryJSON
	if err := json.Unmarshal(data, &wire); err != nil {
		return nil, fmt.Errorf(errFmt, errRegistryDecodePrefix, err)
	}

	g, err := resolveDecodedGroup(receiver, wire.Group)
	if err != nil {
		return nil, fmt.Errorf(errFmt, errRegistryDecodePrefix, err)
	}

	if wire.Total == 0 || wire.Threshold == 0 || wire.Threshold > wire.Total {
		return nil, fmt.Errorf("%w: %w: invalid total or threshold",
			errRegistryDecodePrefix, errEncodingInvalidJSONEncoding)
	}

	if len(wire.PublicKeyShares) != int(wire.Total) {
		return nil, fmt.Errorf("%w: %w: public key share count does not match total",
			errRegistryDecodePrefix, errEncodingInvalidJSONEncoding)
	}

	if err = requireJSONField(wire.VerificationKey); err != nil {
		return nil, fmt.Errorf(errFmt, errRegistryDecodePrefix, err)
	}

	gpk := g.NewElement()
	if err = json.Unmarshal(wire.VerificationKey, gpk); err != nil {
		return nil, fmt.Errorf("%w: invalid group public key encoding: %w", errRegistryDecodePrefix, err)
	}

	pks := make(map[uint16]*PublicKeyShare, wire.Total)
	for id, raw := range wire.PublicKeyShares {
		var shareWire publicKeyShareJSON
		if err = json.Unmarshal(raw, &shareWire); err != nil {
			return nil, fmt.Errorf("%w: could not decode public key share %d: %w", errRegistryDecodePrefix, id, err)
		}

		if shareWire.ID != id {
			return nil, fmt.Errorf(
				"%w: %w: public key share map key %d does not match share ID %d",
				errRegistryDecodePrefix, errEncodingInvalidJSONEncoding, id, shareWire.ID,
			)
		}

		pk := newPublicKeyShareReceiver(g)
		if err = json.Unmarshal(raw, pk); err != nil {
			return nil, fmt.Errorf("%w: could not decode public key share %d: %w", errRegistryDecodePrefix, id, err)
		}

		if len(pk.vssCommitment) != int(wire.Threshold) {
			return nil, fmt.Errorf(
				"%w: %w: public key share %d commitment length does not match threshold",
				errRegistryDecodePrefix, errEncodingInvalidJSONEncoding, id,
			)
		}

		if _, ok := pks[pk.id]; ok {
			return nil, fmt.Errorf(errFmt, errRegistryDecodePrefix, errEncodingPKSDuplication)
		}

		pks[pk.id] = pk
	}

	registry := &PublicKeyShareRegistry{
		verificationKey: gpk,
		publicKeyShares: pks,
		total:           wire.Total,
		threshold:       wire.Threshold,
		group:           g,
	}
	if err = registry.Validate(); err != nil {
		return nil, err
	}

	return registry, nil
}
