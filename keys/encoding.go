// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package keys

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"

	"github.com/bytemare/ecc"
)

var (
	errEncodingInvalidGroup                  = errors.New("invalid group identifier")
	errEncodingInvalidLength                 = errors.New("invalid encoding length")
	errEncodingInvalidJSONEncoding           = errors.New("invalid JSON encoding")
	errEncodingGroupMismatch                 = errors.New("encoded group does not match receiver group")
	errInvalidPolynomialLength               = errors.New("invalid polynomial length (exceeds uint16 limit 65535)")
	errPublicKeyShareDecodePrefix            = errors.New("failed to decode PublicKeyShare")
	errKeyShareDecodePrefix                  = errors.New("failed to decode KeyShare")
	errRegistryDecodePrefix                  = errors.New("failed to decode PublicKeyShareRegistry")
	errPublicKeyShareRegistered              = errors.New("the public key share is already registered")
	errNilPublicKeyShare                     = errors.New("public key share is nil")
	errNilKeyShare                           = errors.New("key share is nil")
	errNilRegistry                           = errors.New("public key share registry is nil")
	errInvalidIdentifier                     = errors.New("identifier is zero or exceeds registry total")
	errInvalidRegistryParameters             = errors.New("invalid total or threshold")
	errCommitmentLengthDoesNotMatchThreshold = errors.New(
		"public key share commitment length does not match threshold",
	)
	errRegistryShareCountDoesNotMatchTotal     = errors.New("public key share count does not match total")
	errRegistryMapKeyDoesNotMatchShareID       = errors.New("public key share map key does not match share ID")
	errInvalidVSSShare                         = errors.New("public key share does not verify against commitment")
	errVerificationKeyDoesNotMatchCommitment   = errors.New("verification key does not match commitment")
	errCommitmentsDoNotMatch                   = errors.New("public key shares do not have the same commitment")
	errPublicKeyDoesNotMatchSecret             = errors.New("public key does not match secret key")
	errEncodingNonCanonicalPublicKeyShareOrder = errors.New("encoded public key shares are not in canonical order")
	errInvalidRegistry                         = errors.New("invalid public key share registry")
	errVerifyUnknownID                         = errors.New("the requested identifier is not registered")
	errNilPubKey                               = errors.New("the provided public key is nil")
	errRegistryHasNilPublicKey                 = errors.New("encountered a nil public key in registry")
	errVerifyBadPubKey                         = errors.New("the public key differs from the one registered")
	errEncodingPKSDuplication                  = errors.New("multiple encoded public key shares with same ID")
)

const errFmt = "%w: %w"

// helper functions

type publicKeyShareJSON struct {
	PublicKey     json.RawMessage   `json:"publicKey"`
	VssCommitment []json.RawMessage `json:"vssCommitment,omitempty"`
	ID            uint16            `json:"id"`
	Group         ecc.Group         `json:"group"`
}

type keyShareJSON struct {
	Secret          json.RawMessage `json:"secret"`
	VerificationKey json.RawMessage `json:"verificationKey"`
}

type registryJSON struct {
	PublicKeyShares map[uint16]json.RawMessage `json:"publicKeyShares"`
	VerificationKey json.RawMessage            `json:"verificationKey"`
	Total           uint16                     `json:"total"`
	Threshold       uint16                     `json:"threshold"`
	Group           ecc.Group                  `json:"group"`
}

func resolveDecodedGroup(receiver, encoded ecc.Group) (ecc.Group, error) {
	if !encoded.Available() {
		return 0, errEncodingInvalidGroup
	}

	if receiver == 0 {
		return encoded, nil
	}

	if !receiver.Available() {
		return 0, errEncodingInvalidGroup
	}

	if encoded != receiver {
		return 0, errEncodingGroupMismatch
	}

	return receiver, nil
}

func requireJSONField(raw json.RawMessage) error {
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return errEncodingInvalidJSONEncoding
	}

	return nil
}

func decodeKeyShareHeader(data []byte) (g ecc.Group, pksLen, comLen int, err error) {
	if len(data) == 0 {
		return 0, 0, 0, errEncodingInvalidLength
	}

	g = ecc.Group(data[0])
	if !g.Available() {
		return 0, 0, 0, errEncodingInvalidGroup
	}

	if len(data) <= sharedHeaderLength {
		return 0, 0, 0, errEncodingInvalidLength
	}

	comLen = int(binary.LittleEndian.Uint16(data[3:sharedHeaderLength]))
	pksLen = publicKeyShareLength(g, comLen)

	return g, pksLen, comLen, nil
}
