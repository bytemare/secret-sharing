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
	"math"

	"github.com/bytemare/ecc"
)

// PublicKeyShare specifies the public key of a participant identified with ID.
// This can be used in a registry of participants.
type PublicKeyShare struct {
	// The PublicKey of Secret belonging to the participant.
	PublicKey *ecc.Element `json:"publicKey"`

	// The VssCommitment to the polynomial the key was created with.
	VssCommitment []*ecc.Element `json:"vssCommitment,omitempty"`

	// ID of the participant.
	ID uint16 `json:"id"`

	// Group specifies the elliptic curve group the public key and commitments are part of.
	Group ecc.Group `json:"group"`
}

// NewPublicKeyShare returns a PublicKeyShare receiver pinned to g for JSON decoding.
// When passed to json.Unmarshal, the encoded top-level group and every encoded element must belong to g.
// Use a zero-value receiver instead when the group should be inferred from self-describing JSON.
func NewPublicKeyShare(g ecc.Group) *PublicKeyShare {
	p := &PublicKeyShare{Group: g}
	if g.Available() {
		p.PublicKey = g.NewElement()
	}

	return p
}

func publicKeyShareLength(g ecc.Group, polyLen int) int {
	eLen := g.ElementLength()
	return 1 + 2 + 2 + eLen + polyLen*eLen
}

// Encode serializes p into a compact byte string.
func (p *PublicKeyShare) Encode() []byte {
	out := make([]byte, 5, publicKeyShareLength(p.Group, len(p.VssCommitment)))
	out[0] = byte(p.Group)
	binary.LittleEndian.PutUint16(out[1:3], p.ID)
	binary.LittleEndian.PutUint16(out[3:5], uint16(len(p.VssCommitment)))
	out = append(out, p.PublicKey.Encode()...)

	for _, c := range p.VssCommitment {
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

// UnmarshalJSON decodes data into p, or returns an error.
// If p.Group is zero, the group is inferred from the encoded top-level group.
// If p.Group is non-zero, it must identify an available group and match the encoded top-level group.
// Every encoded element group must match the resolved group.
func (p *PublicKeyShare) UnmarshalJSON(data []byte) error {
	decoded, err := decodePublicKeyShareJSON(p.Group, data)
	if err != nil {
		return fmt.Errorf(errFmt, errPublicKeyShareDecodePrefix, err)
	}

	*p = *decoded

	return nil
}

func decodePublicKeyShareJSON(receiver ecc.Group, data []byte) (*PublicKeyShare, error) {
	var wire publicKeyShareJSON
	if err := json.Unmarshal(data, &wire); err != nil {
		return nil, err
	}

	g, err := resolveDecodedGroup(receiver, wire.Group)
	if err != nil {
		return nil, err
	}

	if err := requireJSONField(wire.PublicKey); err != nil {
		return nil, err
	}

	if len(wire.VssCommitment) > math.MaxUint16 {
		return nil, errInvalidPolynomialLength
	}

	pk := g.NewElement()
	if err := json.Unmarshal(wire.PublicKey, pk); err != nil {
		return nil, fmt.Errorf("failed to decode public key: %w", err)
	}

	commitment := make([]*ecc.Element, len(wire.VssCommitment))
	for i, raw := range wire.VssCommitment {
		c := g.NewElement()
		if err := json.Unmarshal(raw, c); err != nil {
			return nil, fmt.Errorf("failed to decode commitment %d: %w", i+1, err)
		}

		commitment[i] = c
	}

	return &PublicKeyShare{
		PublicKey:     pk,
		VssCommitment: commitment,
		ID:            wire.ID,
		Group:         g,
	}, nil
}

func (p *PublicKeyShare) decode(g ecc.Group, cLen int, data []byte) error {
	g, err := resolveDecodedGroup(p.Group, g)
	if err != nil {
		return fmt.Errorf(errFmt, errPublicKeyShareDecodePrefix, err)
	}

	eLen := g.ElementLength()
	id := binary.LittleEndian.Uint16(data[1:3])

	pk := g.NewElement()
	if err := pk.Decode(data[5 : 5+eLen]); err != nil {
		return fmt.Errorf("%w: failed to decode public key: %w", errPublicKeyShareDecodePrefix, err)
	}

	i := 0
	commitment := make([]*ecc.Element, cLen)

	for j := 7 + eLen; j < len(data); j += eLen {
		c := g.NewElement()
		if err := c.Decode(data[j : j+eLen]); err != nil {
			return fmt.Errorf("%w: failed to decode commitment %d: %w", errPublicKeyShareDecodePrefix, i+1, err)
		}

		commitment[i] = c
		i++
	}

	p.Group = g
	p.ID = id
	p.PublicKey = pk
	p.VssCommitment = commitment

	return nil
}
