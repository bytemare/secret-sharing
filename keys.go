// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package secretsharing

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	group "github.com/bytemare/crypto"
)

var (
	errEncodingInvalidGroup        = errors.New("invalid group identifier")
	errEncodingInvalidLength       = errors.New("invalid encoding length")
	errEncodingInvalidCommitment   = errors.New("invalid encoding of commitments")
	errEncodingInvalidJSONEncoding = errors.New("invalid JSON encoding")
)

// The Share interface enables to use functions in this package with compatible key shares.
type Share interface {
	// Identifier returns the identity for this share.
	Identifier() uint64

	// SecretKey returns the participant's secret share.
	SecretKey() *group.Scalar
}

// PublicKeyShare specifies the public key of a participant identified with ID. This can be useful to keep a registry of
// participants.
type PublicKeyShare struct {
	// The PublicKey of Secret belonging to the participant.
	PublicKey *group.Element `json:"publicKey"`

	// The Commitment to the polynomial the key was created with.
	Commitment []*group.Element `json:"commitment"`

	// ID of the participant.
	ID uint64 `json:"id"`

	// Group specifies the elliptic curve group the elements are part of.
	Group group.Group `json:"group"`
}

// Verify returns whether the PublicKeyShare's public key is valid given its VSS commitment to the secret polynomial.
func (p *PublicKeyShare) Verify() bool {
	return Verify(p.Group, p.ID, p.PublicKey, p.Commitment)
}

// Encode serializes p into a compact byte string.
func (p *PublicKeyShare) Encode() []byte {
	eLen := p.Group.ElementLength()
	oLen := 1 + 8 + 4 + eLen + len(p.Commitment)*eLen
	out := make([]byte, 13, oLen)
	out[0] = byte(p.Group)
	binary.LittleEndian.PutUint64(out[1:9], p.ID)
	binary.LittleEndian.PutUint32(out[9:13], uint32(len(p.Commitment)))
	out = append(out, p.PublicKey.Encode()...)

	for _, c := range p.Commitment {
		out = append(out, c.Encode()...)
	}

	return out
}

func (p *PublicKeyShare) decode(g group.Group, cLen int, data []byte) error {
	eLen := g.ElementLength()
	id := binary.LittleEndian.Uint64(data[1:9])

	pk := g.NewElement()
	if err := pk.Decode(data[13 : 13+eLen]); err != nil {
		return fmt.Errorf("failed to decode public key: %w", err)
	}

	i := 0
	commitment := make([]*group.Element, cLen)

	for j := 13 + eLen; j < len(data); j += eLen {
		c := g.NewElement()
		if err := c.Decode(data[j : j+eLen]); err != nil {
			return fmt.Errorf("failed to decode commitment %d: %w", i+1, err)
		}

		commitment[i] = c
		i++
	}

	p.Group = g
	p.ID = id
	p.PublicKey = pk
	p.Commitment = commitment

	return nil
}

// Decode deserializes the compact encoding obtained from Encode(), or returns an error.
func (p *PublicKeyShare) Decode(data []byte) error {
	g, expectedLength, cLen, err := decodeKeyShareHeader(data)
	if err != nil {
		return err
	}

	if len(data) != expectedLength {
		return errEncodingInvalidLength
	}

	return p.decode(g, cLen, data)
}

type publicKeyShareShadow PublicKeyShare

func initPkShadow(g group.Group, threshold int) *publicKeyShareShadow {
	p := &publicKeyShareShadow{
		ID:         0,
		Group:      g,
		PublicKey:  g.NewElement(),
		Commitment: make([]*group.Element, threshold),
	}

	for i := range threshold {
		p.Commitment[i] = g.NewElement()
	}

	return p
}

// UnmarshalJSON decodes data into p, or returns an error.
func (p *PublicKeyShare) UnmarshalJSON(data []byte) error {
	s := string(data)

	g, err := jsonReGetGroup(s)
	if err != nil {
		return err
	}

	nPoly, err := jsonRePolyLen(s)
	if err != nil {
		return err
	}

	ps := initPkShadow(g, nPoly)
	if err = json.Unmarshal(data, ps); err != nil {
		return fmt.Errorf("failed to decode PublicKeyShare: %w", err)
	}

	*p = PublicKeyShare(*ps)

	return nil
}

// KeyShare holds the secret and public key share for a given participant.
type KeyShare struct {
	Secret         *group.Scalar  `json:"secret"`
	GroupPublicKey *group.Element `json:"groupPublicKey"`
	PublicKeyShare
}

// Identifier returns the identity for this share.
func (k *KeyShare) Identifier() uint64 {
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

// Decode deserializes the compact encoding obtained from Encode(), or returns an error.
func (k *KeyShare) Decode(data []byte) error {
	g, pkLen, cLen, _err := decodeKeyShareHeader(data)
	if _err != nil {
		return _err
	}

	expectedLength := pkLen + g.ScalarLength() + g.ElementLength()
	if len(data) != expectedLength {
		return errEncodingInvalidLength
	}

	pk := new(PublicKeyShare)
	if err := pk.decode(g, cLen, data[:pkLen]); err != nil {
		return err
	}

	s := g.NewScalar()
	if err := s.Decode(data[pkLen : pkLen+g.ScalarLength()]); err != nil {
		return fmt.Errorf("failed to decode Secret in KeyShare: %w", err)
	}

	e := g.NewElement()
	if err := e.Decode(data[pkLen+g.ScalarLength():]); err != nil {
		return fmt.Errorf("failed to decode GroupPublicKey in KeyShare: %w", err)
	}

	k.populate(s, e, pk)

	return nil
}

func (k *KeyShare) populate(s *group.Scalar, gpk *group.Element, pks *PublicKeyShare) {
	k.Secret = s
	k.GroupPublicKey = gpk
	k.PublicKeyShare = *pks
}

type keyShareShadow struct {
	Secret         *group.Scalar  `json:"secret"`
	GroupPublicKey *group.Element `json:"groupPublicKey"`
}

// UnmarshalJSON decodes data into k, or returns an error.
func (k *KeyShare) UnmarshalJSON(data []byte) error {
	pk := new(PublicKeyShare)
	if err := json.Unmarshal(data, pk); err != nil {
		return fmt.Errorf("failed to unmarshall KeyShare: %w", err)
	}

	ks := &keyShareShadow{
		Secret:         pk.Group.NewScalar(),
		GroupPublicKey: pk.Group.NewElement(),
	}

	if err := json.Unmarshal(data, ks); err != nil {
		return fmt.Errorf("failed to unmarshall KeyShare: %w", err)
	}

	k.populate(ks.Secret, ks.GroupPublicKey, pk)

	return nil
}

func jsonReGetField(key, s, catch string) (string, error) {
	r := fmt.Sprintf(`%q:%s`, key, catch)
	re := regexp.MustCompile(r)
	matches := re.FindStringSubmatch(s)

	if len(matches) != 2 {
		return "", errEncodingInvalidJSONEncoding
	}

	return matches[1], nil
}

// jsonReGetGroup attempts to find the Group JSON encoding in s.
func jsonReGetGroup(s string) (group.Group, error) {
	f, err := jsonReGetField("group", s, `(\w+)`)
	if err != nil {
		return 0, err
	}

	i, err := strconv.Atoi(f)
	if err != nil {
		return 0, fmt.Errorf("failed to read Group: %w", err)
	}

	if i < 0 || i > 63 {
		return 0, errEncodingInvalidGroup
	}

	g := group.Group(i)
	if !g.Available() {
		return 0, errEncodingInvalidGroup
	}

	return g, nil
}

// jsonRePolyLen attempts to find the number of elements encoded in the commitment.
func jsonRePolyLen(s string) (int, error) {
	re := regexp.MustCompile(`commitment":\[\s*(.*?)\s*]`)

	matches := re.FindStringSubmatch(s)
	if len(matches) != 2 {
		return 0, errEncodingInvalidCommitment
	}

	n := strings.Count(matches[1], ",")
	if n == 0 {
		return 0, errEncodingInvalidCommitment
	}

	return n + 1, nil
}

func decodeKeyShareHeader(data []byte) (group.Group, int, int, error) {
	if len(data) == 0 {
		return 0, 0, 0, errEncodingInvalidLength
	}

	g := group.Group(data[0])
	if !g.Available() {
		return 0, 0, 0, errEncodingInvalidGroup
	}

	if len(data) <= 13 {
		return 0, 0, 0, errEncodingInvalidLength
	}

	cLen := int(binary.LittleEndian.Uint32(data[9:13]))
	eLen := g.ElementLength()
	pks := 1 + 8 + 4 + eLen + cLen*eLen

	return g, pks, cLen, nil
}
