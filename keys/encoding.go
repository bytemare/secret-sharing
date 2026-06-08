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

	"github.com/bytemare/ecc"
)

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
