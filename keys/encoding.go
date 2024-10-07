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
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/bytemare/ecc"
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

// helper functions

type shadowInit interface {
	init(g ecc.Group, threshold uint16)
}

type publicKeyShareShadow PublicKeyShare

func (p *publicKeyShareShadow) init(g ecc.Group, threshold uint16) {
	p.ID = 0
	p.Group = g
	p.PublicKey = g.NewElement()
	p.VssCommitment = make([]*ecc.Element, threshold)

	for i := range threshold {
		p.VssCommitment[i] = g.NewElement()
	}
}

type keyShareShadow struct {
	Secret          *ecc.Scalar  `json:"secret"`
	VerificationKey *ecc.Element `json:"verificationKey"`
	*publicKeyShareShadow
}

func (k *keyShareShadow) init(g ecc.Group, threshold uint16) {
	p := new(publicKeyShareShadow)
	p.init(g, threshold)
	k.Secret = g.NewScalar()
	k.VerificationKey = g.NewElement()
	k.publicKeyShareShadow = p
}

type registryShadow PublicKeyShareRegistry

func (r *registryShadow) init(g ecc.Group, _ uint16) {
	r.VerificationKey = g.NewElement()
}

func unmarshalJSONHeader(data []byte) (ecc.Group, uint16, error) {
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
func jsonReGetGroup(s string) (ecc.Group, error) {
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

	g := ecc.Group(i)
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

func decodeKeyShareHeader(data []byte) (ecc.Group, int, int, error) {
	if len(data) == 0 {
		return 0, 0, 0, errEncodingInvalidLength
	}

	g := ecc.Group(data[0])
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
