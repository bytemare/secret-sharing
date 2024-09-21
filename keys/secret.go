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
	"fmt"
	"slices"

	group "github.com/bytemare/crypto"
)

// The Share interface enables to use functions in this package with compatible key shares.
type Share interface {
	// Group returns the elliptic curve group used for this key share.
	Group() group.Group

	// Identifier returns the identity for this share.
	Identifier() uint16

	// SecretKey returns the participant's secret share.
	SecretKey() *group.Scalar
}

// KeyShare holds the secret and public key share for a given participant.
type KeyShare struct {
	Secret         *group.Scalar  `json:"secret"`
	GroupPublicKey *group.Element `json:"groupPublicKey"`
	PublicKeyShare
}

// Group returns the elliptic curve group used for this key share.
func (k *KeyShare) Group() group.Group {
	return k.PublicKeyShare.Group
}

// Identifier returns the identity for this share.
func (k *KeyShare) Identifier() uint16 {
	return k.ID
}

// SecretKey returns the participant's secret share.
func (k *KeyShare) SecretKey() *group.Scalar {
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
	out = append(out, k.GroupPublicKey.Encode()...)

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
		return fmt.Errorf("%w: failed to decode GroupPublicKey: %w", errKeyShareDecodePrefix, err)
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

func (k *KeyShare) populate(s *group.Scalar, gpk *group.Element, pks *PublicKeyShare) {
	k.Secret = s
	k.GroupPublicKey = gpk
	k.PublicKeyShare = *pks
}

// UnmarshalJSON decodes data into k, or returns an error.
func (k *KeyShare) UnmarshalJSON(data []byte) error {
	ks := new(keyShareShadow)
	if err := unmarshalJSON(data, ks); err != nil {
		return fmt.Errorf(errFmt, errKeyShareDecodePrefix, err)
	}

	k.populate(ks.Secret, ks.GroupPublicKey, (*PublicKeyShare)(ks.publicKeyShareShadow))

	return nil
}
