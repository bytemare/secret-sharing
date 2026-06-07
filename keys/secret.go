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
	secret          *ecc.Scalar
	verificationKey *ecc.Element
	publicKeyShare  PublicKeyShare
}

func newKeyShareReceiver(g ecc.Group) *KeyShare {
	k := &KeyShare{publicKeyShare: *newPublicKeyShareReceiver(g)}
	if g.Available() {
		k.secret = g.NewScalar()
		k.verificationKey = g.NewElement()
	}

	return k
}

// NewKeyShareReceiver returns a KeyShare receiver pinned to g for JSON and compact decoding.
// Use a zero-value receiver instead when the group should be inferred from self-describing input.
func NewKeyShareReceiver(g ecc.Group) *KeyShare {
	return newKeyShareReceiver(g)
}

// NewKeyShare returns a valid key share with defensive copies of the caller's key material.
// The verificationKey is the global public key of the sharded secret key in the secret-sharing setup. It is optional.
// The VSS commitment is optional.
func NewKeyShare(
	g ecc.Group,
	id uint16,
	secret *ecc.Scalar,
	verificationKey *ecc.Element,
	commitment []*ecc.Element,
) (*KeyShare, error) {
	if err := validateScalar(g, secret, "secret key"); err != nil {
		return nil, err
	}

	publicKey := g.Base().Multiply(secret)

	publicShare, err := NewPublicKeyShare(g, id, publicKey, commitment)
	if err != nil {
		return nil, err
	}

	share := &KeyShare{
		secret:          cloneScalar(secret),
		verificationKey: verificationKey,
		publicKeyShare:  *publicShare,
	}
	if verificationKey != nil {
		share.verificationKey = cloneElement(verificationKey)
	}

	if err = share.Validate(); err != nil {
		return nil, err
	}

	return share, nil
}

// Group returns the elliptic curve group used for this key share.
func (k *KeyShare) Group() ecc.Group {
	if k == nil {
		return 0
	}

	return k.publicKeyShare.group
}

// Identifier returns the identity for this share.
func (k *KeyShare) Identifier() uint16 {
	if k == nil {
		return 0
	}

	return k.publicKeyShare.id
}

// SecretKey returns a defensive copy of the participant's secret share.
func (k *KeyShare) SecretKey() *ecc.Scalar {
	if k == nil {
		return nil
	}

	return cloneScalar(k.secret)
}

// VerificationKey returns a defensive copy of the group verification key.
func (k *KeyShare) VerificationKey() *ecc.Element {
	if k == nil {
		return nil
	}

	return cloneElement(k.verificationKey)
}

// PublicKey returns a defensive copy of the participant's public key.
func (k *KeyShare) PublicKey() *ecc.Element {
	if k == nil {
		return nil
	}

	return k.publicKeyShare.PublicKey()
}

// Commitment returns a defensive copy of the VSS commitment.
func (k *KeyShare) Commitment() []*ecc.Element {
	if k == nil {
		return nil
	}

	return k.publicKeyShare.Commitment()
}

// PublicKeyShare returns a defensive copy of the public key share and identifier corresponding to the secret key share.
func (k *KeyShare) PublicKeyShare() *PublicKeyShare {
	if k == nil {
		return nil
	}

	return clonePublicKeyShare(&k.publicKeyShare)
}

// Validate returns an error unless k satisfies the key share invariants.
func (k *KeyShare) Validate() error {
	return validateKeyShare(k)
}

// Encode serializes k into a compact byte string.
func (k *KeyShare) Encode() []byte {
	if err := k.Validate(); err != nil {
		return nil
	}

	pk := k.publicKeyShare.Encode()
	eLen := k.publicKeyShare.group.ElementLength()
	sLen := k.publicKeyShare.group.ScalarLength()
	out := slices.Grow(pk, eLen+sLen)
	out = append(out, k.secret.Encode()...)
	out = append(out, k.verificationKey.Encode()...)

	return out
}

// Hex returns the hexadecimal representation of the byte encoding returned by Encode().
func (k *KeyShare) Hex() string {
	return hex.EncodeToString(k.Encode())
}

// Decode deserializes the compact encoding obtained from Encode(), or returns an error.
func (k *KeyShare) Decode(data []byte) error {
	if k == nil {
		return fmt.Errorf(errFmt, errKeyShareDecodePrefix, errNilKeyShare)
	}

	g, pkLen, cLen, err := decodeKeyShareHeader(data)
	if err != nil {
		return fmt.Errorf(errFmt, errKeyShareDecodePrefix, err)
	}

	expectedLength := pkLen + g.ScalarLength() + g.ElementLength()
	if len(data) != expectedLength {
		return fmt.Errorf(errFmt, errKeyShareDecodePrefix, errEncodingInvalidLength)
	}

	pk := &PublicKeyShare{group: k.Group()}
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

	share := new(KeyShare).populate(s, e, pk)
	if err = share.Validate(); err != nil {
		return fmt.Errorf(errFmt, errKeyShareDecodePrefix, err)
	}

	*k = *share

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
	if k == nil {
		return fmt.Errorf(errFmt, errKeyShareDecodePrefix, errNilKeyShare)
	}

	pk, err := decodePublicKeyShareJSON(k.Group(), data)
	if err != nil {
		return fmt.Errorf(errFmt, errKeyShareDecodePrefix, err)
	}

	g := pk.group

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

	share := new(KeyShare).populate(s, e, pk)
	if err = share.Validate(); err != nil {
		return fmt.Errorf(errFmt, errKeyShareDecodePrefix, err)
	}

	*k = *share

	return nil
}

// MarshalJSON encodes k using the stable flattened public wire contract.
func (k *KeyShare) MarshalJSON() ([]byte, error) {
	if err := k.Validate(); err != nil {
		return nil, err
	}

	encoded, err := json.Marshal(struct {
		Secret          *ecc.Scalar    `json:"secret"`
		VerificationKey *ecc.Element   `json:"verificationKey"`
		PublicKey       *ecc.Element   `json:"publicKey"`
		VssCommitment   []*ecc.Element `json:"vssCommitment,omitempty"`
		ID              uint16         `json:"id"`
		Group           ecc.Group      `json:"group"`
	}{
		Secret:          k.secret,
		VerificationKey: k.verificationKey,
		PublicKey:       k.publicKeyShare.publicKey,
		VssCommitment:   k.publicKeyShare.vssCommitment,
		ID:              k.publicKeyShare.id,
		Group:           k.publicKeyShare.group,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to JSON encode KeyShare: %w", err)
	}

	return encoded, nil
}

func (k *KeyShare) populate(s *ecc.Scalar, gpk *ecc.Element, pks *PublicKeyShare) *KeyShare {
	k.secret = s
	k.verificationKey = gpk
	k.publicKeyShare = *pks

	return k
}
