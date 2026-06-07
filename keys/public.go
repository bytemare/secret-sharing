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
	"errors"
	"fmt"
	"math"

	"github.com/bytemare/ecc"
)

const sharedHeaderLength = 5

var errDecodePublicKey = errors.New("failed to decode public key")

// PublicKeyShare specifies the public key of a participant identified with ID.
// This can be used in a registry of participants.
type PublicKeyShare struct {
	publicKey     *ecc.Element
	vssCommitment []*ecc.Element
	id            uint16
	group         ecc.Group
}

func newPublicKeyShareReceiver(g ecc.Group) *PublicKeyShare {
	p := &PublicKeyShare{group: g}
	if g.Available() {
		p.publicKey = g.NewElement()
	}

	return p
}

// NewPublicKeyShareReceiver returns a PublicKeyShare receiver pinned to g for JSON and compact decoding.
// Use a zero-value receiver instead when the group should be inferred from self-describing input.
func NewPublicKeyShareReceiver(g ecc.Group) *PublicKeyShare {
	return newPublicKeyShareReceiver(g)
}

// NewPublicKeyShare returns a valid public key share with defensive copies of the caller's key material.
func NewPublicKeyShare(
	g ecc.Group,
	id uint16,
	publicKey *ecc.Element,
	commitment []*ecc.Element,
) (*PublicKeyShare, error) {
	share := &PublicKeyShare{
		publicKey:     publicKey,
		vssCommitment: commitment,
		id:            id,
		group:         g,
	}
	if err := share.Validate(); err != nil {
		return nil, err
	}

	return clonePublicKeyShare(share), nil
}

// Group returns the elliptic curve group used for this public key share.
func (p *PublicKeyShare) Group() ecc.Group {
	if p == nil {
		return 0
	}

	return p.group
}

// Identifier returns the identity for this public key share.
func (p *PublicKeyShare) Identifier() uint16 {
	if p == nil {
		return 0
	}

	return p.id
}

// PublicKey returns a defensive copy of the participant's public key.
func (p *PublicKeyShare) PublicKey() *ecc.Element {
	if p == nil || p.publicKey == nil {
		return nil
	}

	return cloneElement(p.publicKey)
}

// Commitment returns a defensive copy of the VSS commitment.
func (p *PublicKeyShare) Commitment() []*ecc.Element {
	if p == nil {
		return nil
	}

	return cloneCommitment(p.vssCommitment)
}

// Validate returns an error unless p satisfies the public key share invariants.
func (p *PublicKeyShare) Validate() error {
	return validatePublicKeyShare(p)
}

func publicKeyShareLength(g ecc.Group, polyLen int) int {
	eLen := g.ElementLength()
	return sharedHeaderLength + eLen + polyLen*eLen
}

// Encode serializes p into a compact byte string.
func (p *PublicKeyShare) Encode() []byte {
	if err := p.Validate(); err != nil {
		return nil
	}

	out := make([]byte, sharedHeaderLength, publicKeyShareLength(p.group, len(p.vssCommitment)))
	out[0] = byte(p.group)
	binary.LittleEndian.PutUint16(out[1:3], p.id)
	binary.LittleEndian.PutUint16(out[3:5], uint16(len(p.vssCommitment)))
	out = append(out, p.publicKey.Encode()...)

	for _, c := range p.vssCommitment {
		out = append(out, c.Encode()...)
	}

	return out
}

// Hex returns the hexadecimal representation of the byte encoding returned by Encode().
func (p *PublicKeyShare) Hex() string {
	return hex.EncodeToString(p.Encode())
}

// Decode deserializes the compact encoding obtained from Encode(), or returns an error.
func (p *PublicKeyShare) Decode(data []byte) error {
	if p == nil {
		return fmt.Errorf(errFmt, errPublicKeyShareDecodePrefix, errNilPublicKeyShare)
	}

	g, expectedLength, cLen, err := decodeKeyShareHeader(data)
	if err != nil {
		return fmt.Errorf(errFmt, errPublicKeyShareDecodePrefix, err)
	}

	if len(data) != expectedLength {
		return fmt.Errorf(errFmt, errPublicKeyShareDecodePrefix, errEncodingInvalidLength)
	}

	return p.decode(g, cLen, data)
}

// DecodeHex sets p to the decoding of the hex encoded representation returned by Hex().
func (p *PublicKeyShare) DecodeHex(h string) error {
	b, err := hex.DecodeString(h)
	if err != nil {
		return fmt.Errorf(errFmt, errPublicKeyShareDecodePrefix, err)
	}

	return p.Decode(b)
}

// MarshalJSON encodes p using the stable public wire contract.
func (p *PublicKeyShare) MarshalJSON() ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}

	encoded, err := json.Marshal(struct {
		PublicKey     *ecc.Element   `json:"publicKey"`
		VssCommitment []*ecc.Element `json:"vssCommitment,omitempty"`
		ID            uint16         `json:"id"`
		Group         ecc.Group      `json:"group"`
	}{
		PublicKey:     p.publicKey,
		VssCommitment: p.vssCommitment,
		ID:            p.id,
		Group:         p.group,
	})
	if err != nil {
		return nil, fmt.Errorf("json marshaling public key share: %w", err)
	}

	return encoded, nil
}

// UnmarshalJSON decodes data into p, or returns an error.
// If p.Group() is zero, the group is inferred from the encoded top-level group.
// If p.Group() is non-zero, it must identify an available group and match the encoded top-level group.
// Every encoded element group must match the resolved group.
func (p *PublicKeyShare) UnmarshalJSON(data []byte) error {
	if p == nil {
		return fmt.Errorf(errFmt, errPublicKeyShareDecodePrefix, errNilPublicKeyShare)
	}

	decoded, err := decodePublicKeyShareJSON(p.group, data)
	if err != nil {
		return err
	}

	*p = *decoded

	return nil
}

func decodePublicKeyShareJSON(receiver ecc.Group, data []byte) (*PublicKeyShare, error) {
	var wire publicKeyShareJSON
	if err := json.Unmarshal(data, &wire); err != nil {
		return nil, fmt.Errorf(errFmt, errPublicKeyShareDecodePrefix, err)
	}

	g, err := resolveDecodedGroup(receiver, wire.Group)
	if err != nil {
		return nil, fmt.Errorf(errFmt, errPublicKeyShareDecodePrefix, err)
	}

	if err = requireJSONField(wire.PublicKey); err != nil {
		return nil, fmt.Errorf(errFmt, errPublicKeyShareDecodePrefix, err)
	}

	if len(wire.VssCommitment) > math.MaxUint16 {
		return nil, fmt.Errorf(errFmt, errPublicKeyShareDecodePrefix, errInvalidPolynomialLength)
	}

	pk := g.NewElement()
	if err = json.Unmarshal(wire.PublicKey, pk); err != nil {
		return nil, fmt.Errorf("%w: %w: %w", errPublicKeyShareDecodePrefix, errDecodePublicKey, err)
	}

	commitment := make([]*ecc.Element, len(wire.VssCommitment))
	for i, raw := range wire.VssCommitment {
		if err = requireJSONField(raw); err != nil {
			return nil, fmt.Errorf("%w, failed to decode commitment %d: %w", errPublicKeyShareDecodePrefix, i+1, err)
		}

		c := g.NewElement()
		if err = json.Unmarshal(raw, c); err != nil {
			return nil, fmt.Errorf("%w: failed to decode commitment %d: %w", errPublicKeyShareDecodePrefix, i+1, err)
		}

		commitment[i] = c
	}

	share := &PublicKeyShare{
		publicKey:     pk,
		vssCommitment: commitment,
		id:            wire.ID,
		group:         g,
	}
	if err = share.Validate(); err != nil {
		return nil, fmt.Errorf(errFmt, errPublicKeyShareDecodePrefix, err)
	}

	return share, nil
}

func (p *PublicKeyShare) decode(g ecc.Group, cLen int, data []byte) error {
	g, err := resolveDecodedGroup(p.group, g)
	if err != nil {
		return fmt.Errorf(errFmt, errPublicKeyShareDecodePrefix, err)
	}

	eLen := g.ElementLength()
	id := binary.LittleEndian.Uint16(data[1:3])

	pk := g.NewElement()
	if err = pk.Decode(data[sharedHeaderLength : sharedHeaderLength+eLen]); err != nil {
		return fmt.Errorf("%w: %w: %w", errPublicKeyShareDecodePrefix, errDecodePublicKey, err)
	}

	i := 0
	commitment := make([]*ecc.Element, cLen)

	for j := sharedHeaderLength + eLen; j < len(data); j += eLen {
		c := g.NewElement()
		if err = c.Decode(data[j : j+eLen]); err != nil {
			return fmt.Errorf("%w: failed to decode commitment %d: %w", errPublicKeyShareDecodePrefix, i+1, err)
		}

		commitment[i] = c
		i++
	}

	share := &PublicKeyShare{
		publicKey:     pk,
		vssCommitment: commitment,
		id:            id,
		group:         g,
	}
	if err = share.Validate(); err != nil {
		return fmt.Errorf(errFmt, errPublicKeyShareDecodePrefix, err)
	}

	*p = *share

	return nil
}
