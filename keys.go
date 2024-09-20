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
	"encoding/hex"
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
	errEncodingInvalidGroup           = errors.New("invalid group identifier")
	errEncodingInvalidLength          = errors.New("invalid encoding length")
	errEncodingInvalidJSONEncoding    = errors.New("invalid JSON encoding")
	errInvalidPolynomialLength        = errors.New("invalid polynomial length (exceeds uint16 limit 65535)")
	errPublicKeyShareDecodePrefix     = errors.New("failed to decode PublicKeyShare")
	errKeyShareDecodePrefix           = errors.New("failed to decode KeyShare")
	errRegistryDecodePrefix           = errors.New("failed to decode PublicKeyShareRegistry")
	errPublicKeyShareRegistered       = errors.New("the public key share is already registered")
	errPublicKeyShareCapacityExceeded = errors.New("can't add another public key share (full capacity)")
	errVerifyUnknownID                = errors.New("the requested identifier is not registered")
	errNilPubKey                      = errors.New("the provided public key is nil")
	errRegistryHasNilPublicKey        = errors.New("encountered a nil public key in registry")
	errVerifyBadPubKey                = errors.New("the public key differs from the one registered")
	errEncodingPKSDuplication         = errors.New("multiple encoded public key shares with same ID")
)

const errFmt = "%w: %w"

// The Share interface enables to use functions in this package with compatible key shares.
type Share interface {
	// Identifier returns the identity for this share.
	Identifier() uint16

	// SecretKey returns the participant's secret share.
	SecretKey() *group.Scalar
}

// PublicKeyShare specifies the public key of a participant identified with ID. This can be useful to keep a registry of
// participants.
type PublicKeyShare struct {
	// The PublicKey of Secret belonging to the participant.
	PublicKey *group.Element `json:"publicKey"`

	// The VssCommitment to the polynomial the key was created with.
	VssCommitment `json:"vssCommitment,omitempty"`

	// ID of the participant.
	ID uint16 `json:"id"`

	// Group specifies the elliptic curve group the elements are part of.
	Group group.Group `json:"group"`
}

// Verify returns whether the PublicKeyShare's public key is valid given its VSS commitment to the secret polynomial.
func (p *PublicKeyShare) Verify() bool {
	return Verify(p.Group, p.ID, p.PublicKey, p.VssCommitment)
}

func publicKeyShareLength(g group.Group, polyLen int) int {
	eLen := g.ElementLength()
	return 1 + 2 + 4 + eLen + polyLen*eLen
}

// Encode serializes p into a compact byte string.
func (p *PublicKeyShare) Encode() []byte {
	out := make([]byte, 7, publicKeyShareLength(p.Group, len(p.VssCommitment)))
	out[0] = byte(p.Group)
	binary.LittleEndian.PutUint16(out[1:3], p.ID)
	binary.LittleEndian.PutUint32(out[3:7], uint32(len(p.VssCommitment)))
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

func (p *PublicKeyShare) decode(g group.Group, cLen int, data []byte) error {
	eLen := g.ElementLength()
	id := binary.LittleEndian.Uint16(data[1:3])

	pk := g.NewElement()
	if err := pk.Decode(data[7 : 7+eLen]); err != nil {
		return fmt.Errorf("%w: failed to decode public key: %w", errPublicKeyShareDecodePrefix, err)
	}

	i := 0
	commitment := make([]*group.Element, cLen)

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
func (p *PublicKeyShare) UnmarshalJSON(data []byte) error {
	ps := new(publicKeyShareShadow)
	if err := unmarshalJSON(data, ps); err != nil {
		return fmt.Errorf(errFmt, errPublicKeyShareDecodePrefix, err)
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

// helper functions

type shadowInit interface {
	init(g group.Group, threshold uint16)
}

type publicKeyShareShadow PublicKeyShare

func (p *publicKeyShareShadow) init(g group.Group, threshold uint16) {
	p.ID = 0
	p.Group = g
	p.PublicKey = g.NewElement()
	p.VssCommitment = make([]*group.Element, threshold)

	for i := range threshold {
		p.VssCommitment[i] = g.NewElement()
	}
}

type keyShareShadow struct {
	Secret         *group.Scalar  `json:"secret"`
	GroupPublicKey *group.Element `json:"groupPublicKey"`
	*publicKeyShareShadow
}

func (k *keyShareShadow) init(g group.Group, threshold uint16) {
	p := new(publicKeyShareShadow)
	p.init(g, threshold)
	k.Secret = g.NewScalar()
	k.GroupPublicKey = g.NewElement()
	k.publicKeyShareShadow = p
}

func unmarshalJSONHeader(data []byte) (group.Group, uint16, error) {
	s := string(data)

	g, err := jsonReGetGroup(s)
	if err != nil {
		return 0, 0, err
	}

	nPoly := jsonRePolyLen(s)
	if nPoly > 65535 {
		return 0, 0, errInvalidPolynomialLength
	}

	return g, uint16(nPoly), nil
}

func unmarshalJSON(data []byte, target shadowInit) error {
	g, nPoly, err := unmarshalJSONHeader(data)
	if err != nil {
		return err
	}

	target.init(g, nPoly)

	if err = json.Unmarshal(data, target); err != nil {
		return fmt.Errorf("%w", err)
	}

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
func jsonRePolyLen(s string) int {
	re := regexp.MustCompile(`vssCommitment":\[\s*(.*?)\s*]`)

	matches := re.FindStringSubmatch(s)
	if len(matches) == 0 {
		return 0
	}

	if matches[1] == "" {
		return 0
	}

	n := strings.Count(matches[1], ",")

	return n + 1
}

func decodeKeyShareHeader(data []byte) (group.Group, int, int, error) {
	if len(data) == 0 {
		return 0, 0, 0, errEncodingInvalidLength
	}

	g := group.Group(data[0])
	if !g.Available() {
		return 0, 0, 0, errEncodingInvalidGroup
	}

	if len(data) <= 7 {
		return 0, 0, 0, errEncodingInvalidLength
	}

	cLen := int(binary.LittleEndian.Uint32(data[3:7]))
	pksLen := publicKeyShareLength(g, cLen)

	return g, pksLen, cLen, nil
}

// PublicKeyShareRegistry regroups the final public information about key shares and participants, enabling a registry
// and public key verifications.
type PublicKeyShareRegistry struct {
	GroupPublicKey  *group.Element             `json:"groupPublicKey"`
	PublicKeyShares map[uint16]*PublicKeyShare `json:"publicKeyShares"`
	Total           uint16                     `json:"total"`
	Threshold       uint16                     `json:"threshold"`
	Group           group.Group                `json:"group"`
}

// NewPublicKeyShareRegistry returns a populated PublicKeyShareRegistry.
func NewPublicKeyShareRegistry(g group.Group, threshold, total uint16) *PublicKeyShareRegistry {
	return &PublicKeyShareRegistry{
		Group:           g,
		Threshold:       threshold,
		Total:           total,
		GroupPublicKey:  nil,
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
func (k *PublicKeyShareRegistry) VerifyPublicKey(id uint16, pubKey *group.Element) error {
	for _, ks := range k.PublicKeyShares {
		if ks.ID == id {
			if pubKey == nil {
				return errNilPubKey
			}

			if ks.PublicKey == nil {
				return fmt.Errorf("%w for ID %d", errRegistryHasNilPublicKey, id)
			}

			if ks.PublicKey.Equal(pubKey) != 1 {
				return fmt.Errorf("%w for ID %d", errVerifyBadPubKey, id)
			}

			return nil
		}
	}

	return fmt.Errorf("%w: %q", errVerifyUnknownID, id)
}

func registryByteSize(g group.Group, threshold, total uint16) (int, int) {
	eLen := g.ElementLength()
	pksLen := 1 + 2 + 4 + eLen + int(threshold)*eLen

	return 1 + 2 + 2 + g.ElementLength() + int(total)*pksLen, pksLen
}

// Encode serializes the registry into a compact byte encoding of the registry, suitable for storage or transmissions.
func (k *PublicKeyShareRegistry) Encode() []byte {
	size, _ := registryByteSize(k.Group, k.Threshold, k.Total)
	out := make([]byte, 5, size)
	out[0] = byte(k.Group)
	binary.LittleEndian.PutUint16(out[1:3], k.Total)
	binary.LittleEndian.PutUint16(out[3:5], k.Threshold)
	out = append(out, k.GroupPublicKey.Encode()...)

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

	g := group.Group(data[0])
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
	k.GroupPublicKey = gpk
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

type registryShadow PublicKeyShareRegistry

// UnmarshalJSON reads the input data as JSON and deserializes it into the receiver. It doesn't modify the receiver when
// encountering an error.
func (k *PublicKeyShareRegistry) UnmarshalJSON(data []byte) error {
	s := string(data)

	g, err := jsonReGetGroup(s)
	if err != nil {
		return fmt.Errorf(errFmt, errRegistryDecodePrefix, err)
	}

	r := new(registryShadow)
	r.GroupPublicKey = g.NewElement()

	if err = json.Unmarshal(data, r); err != nil {
		return fmt.Errorf(errFmt, errRegistryDecodePrefix, err)
	}

	*k = PublicKeyShareRegistry(*r)

	return nil
}
