// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package keys defines key material holding structures for secret sharing setups, like public key shares, private, and
// a registry to hold and manage a set of public key shares.
package keys

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/bytemare/ecc"
)

// KeyShare holds the secret and public key share for a given participant.
type KeyShare struct {
	Secret          *ecc.Scalar  `json:"secret"`
	VerificationKey *ecc.Element `json:"verificationKey"`
	PublicKeyShare
}

// NewKeyShare returns a KeyShare receiver pinned to g for JSON decoding.
// When passed to json.Unmarshal, the encoded top-level group and every encoded scalar or element must belong to g.
// Use a zero-value receiver instead when the group should be inferred from self-describing JSON.
func NewKeyShare(g ecc.Group) *KeyShare {
	k := &KeyShare{PublicKeyShare: *NewPublicKeyShare(g)}
	if g.Available() {
		k.Secret = g.NewScalar()
		k.VerificationKey = g.NewElement()
	}

	return k
}

// Group returns the elliptic curve group used for this key share.
func (k *KeyShare) Group() ecc.Group {
	return k.PublicKeyShare.Group
}

// Identifier returns the identity for this share.
func (k *KeyShare) Identifier() uint16 {
	return k.ID
}

// SecretKey returns the participant's secret share.
func (k *KeyShare) SecretKey() *ecc.Scalar {
	return k.Secret
}

// Public returns the public key share and identifier corresponding to the secret key share.
func (k *KeyShare) Public() *PublicKeyShare {
	return &k.PublicKeyShare
}

// Encode serializes k into a compact byte string.
func (k *KeyShare) Encode() []byte {
	pk := k.PublicKeyShare.Encode()
	eLen := k.PublicKeyShare.Group.ElementLength()
	sLen := k.PublicKeyShare.Group.ScalarLength()
	out := slices.Grow(pk, eLen+sLen)
	out = append(out, k.Secret.Encode()...)
	out = append(out, k.VerificationKey.Encode()...)

	return out
}

// Hex returns the hexadecimal representation of the byte encoding returned by Encode().
func (k *KeyShare) Hex() string {
	return hex.EncodeToString(k.Encode())
}

// Decode deserializes the compact encoding obtained from Encode(), or returns an error.
func (k *KeyShare) Decode(data []byte) error {
	g, pkLen, cLen, err := decodeKeyShareHeader(data)
	if err != nil {
		return fmt.Errorf(errFmt, errKeyShareDecodePrefix, err)
	}

	expectedLength := pkLen + g.ScalarLength() + g.ElementLength()
	if len(data) != expectedLength {
		return fmt.Errorf(errFmt, errKeyShareDecodePrefix, errEncodingInvalidLength)
	}

	pk := new(PublicKeyShare)
	if err = pk.decode(g, cLen, data[:pkLen]); err != nil {
		return fmt.Errorf(errFmt, errKeyShareDecodePrefix, err)
	}

	s := g.NewScalar()
	if err = s.Decode(data[pkLen : pkLen+g.ScalarLength()]); err != nil {
		return fmt.Errorf("%w: failed to decode secret key: %w", errKeyShareDecodePrefix, err)
	}

	e := g.NewElement()
	if err = e.Decode(data[pkLen+g.ScalarLength():]); err != nil {
		return fmt.Errorf("%w: failed to decode VerificationKey: %w", errKeyShareDecodePrefix, err)
	}

	k.populate(s, e, pk)

	return nil
}

// DecodeHex sets k to the decoding of the hex encoded representation returned by Hex().
func (k *KeyShare) DecodeHex(h string) error {
	b, err := hex.DecodeString(h)
	if err != nil {
		return fmt.Errorf(errFmt, errKeyShareDecodePrefix, err)
	}

	return k.Decode(b)
}

// UnmarshalJSON decodes data into k, or returns an error.
// If k.Group() is zero, the group is inferred from the encoded top-level group.
// If k.Group() is non-zero, it must identify an available group and match the encoded top-level group.
// Every encoded scalar or element group must match the resolved group.
func (k *KeyShare) UnmarshalJSON(data []byte) error {
	pk, err := decodePublicKeyShareJSON(k.Group(), data)
	if err != nil {
		return fmt.Errorf(errFmt, errKeyShareDecodePrefix, err)
	}

	g := pk.Group

	var wire keyShareJSON
	if err = json.Unmarshal(data, &wire); err != nil {
		return fmt.Errorf(errFmt, errKeyShareDecodePrefix, err)
	}

	if err = requireJSONField(wire.Secret); err != nil {
		return fmt.Errorf(errFmt, errKeyShareDecodePrefix, err)
	}

	if err = requireJSONField(wire.VerificationKey); err != nil {
		return fmt.Errorf(errFmt, errKeyShareDecodePrefix, err)
	}

	s := g.NewScalar()
	if err = json.Unmarshal(wire.Secret, s); err != nil {
		return fmt.Errorf("%w: failed to decode secret key: %w", errKeyShareDecodePrefix, err)
	}

	e := g.NewElement()
	if err = json.Unmarshal(wire.VerificationKey, e); err != nil {
		return fmt.Errorf("%w: failed to decode VerificationKey: %w", errKeyShareDecodePrefix, err)
	}

	k.populate(s, e, pk)

	return nil
}

func (k *KeyShare) populate(s *ecc.Scalar, gpk *ecc.Element, pks *PublicKeyShare) {
	k.Secret = s
	k.VerificationKey = gpk
	k.PublicKeyShare = *pks
}
