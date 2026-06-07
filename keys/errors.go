// SPDX-License-Identifier: MIT
//
// Copyright (C) 2026 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package keys

import (
	"errors"
)

var (
	// ErrEncodingFailure classifies compact, hexadecimal, and JSON encoding or decoding failures.
	ErrEncodingFailure = errors.New("decoding/encoding failure")

	// ErrInvalidRegistry classifies invalid public key share registries.
	ErrInvalidRegistry = errors.New("invalid public key share registry")

	// ErrInvalidMaterial classifies invalid key, share, scalar, or element material.
	ErrInvalidMaterial = errors.New("invalid key/share material")

	// ErrUnknownShare classifies registry lookups for identifiers that are not registered.
	ErrUnknownShare = errors.New("the requested identifier is not registered")
)

const errFmt = "%w: %w"

type classifiedError struct {
	class     error
	secondary error
	message   string
}

func (e classifiedError) Error() string {
	return e.message
}

func (e classifiedError) Is(target error) bool {
	return target == e.class || target == e.secondary
}

var (
	errDecodePublicKey      = classifiedError{message: "failed to decode public key", class: ErrEncodingFailure}
	errEncodingInvalidGroup = classifiedError{
		message:   "invalid group identifier",
		class:     ErrEncodingFailure,
		secondary: ErrInvalidMaterial,
	}
	errEncodingInvalidLength       = classifiedError{message: "invalid encoding length", class: ErrEncodingFailure}
	errEncodingInvalidJSONEncoding = classifiedError{
		message:   "invalid JSON encoding",
		class:     ErrEncodingFailure,
		secondary: ErrInvalidRegistry,
	}
	errEncodingGroupMismatch = classifiedError{
		message:   "encoded group does not match receiver group",
		class:     ErrEncodingFailure,
		secondary: ErrInvalidMaterial,
	}
	errInvalidPolynomialLength = classifiedError{
		message:   "invalid polynomial length (exceeds uint16 limit 65535)",
		class:     ErrEncodingFailure,
		secondary: ErrInvalidMaterial,
	}
	errPublicKeyShareDecodePrefix = classifiedError{
		message: "failed to decode PublicKeyShare",
		class:   ErrEncodingFailure,
	}
	errKeyShareDecodePrefix = classifiedError{message: "failed to decode KeyShare", class: ErrEncodingFailure}
	errRegistryDecodePrefix = classifiedError{
		message: "failed to decode PublicKeyShareRegistry",
		class:   ErrEncodingFailure,
	}
	errPublicKeyShareRegistered = classifiedError{
		message: "the public key share is already registered",
		class:   ErrInvalidRegistry,
	}
	errNilPublicKeyShare = classifiedError{
		message:   "public key share is nil",
		class:     ErrInvalidMaterial,
		secondary: ErrInvalidRegistry,
	}
	errNilKeyShare       = classifiedError{message: "key share is nil", class: ErrInvalidMaterial}
	errNilRegistry       = classifiedError{message: "public key share registry is nil", class: ErrInvalidRegistry}
	errInvalidIdentifier = classifiedError{
		message:   "identifier is zero or exceeds registry total",
		class:     ErrInvalidMaterial,
		secondary: ErrInvalidRegistry,
	}
	errInvalidRegistryParameters = classifiedError{
		message: "invalid total or threshold",
		class:   ErrInvalidRegistry,
	}
	errCommitmentLengthDoesNotMatchThreshold = classifiedError{
		message: "public key share commitment length does not match threshold",
		class:   ErrInvalidRegistry,
	}
	errRegistryShareCountDoesNotMatchTotal = classifiedError{
		message: "public key share count does not match total",
		class:   ErrInvalidRegistry,
	}
	errRegistryMapKeyDoesNotMatchShareID = classifiedError{
		message: "public key share map key does not match share ID",
		class:   ErrInvalidRegistry,
	}
	errInvalidVSSShare = classifiedError{
		message:   "public key share does not verify against commitment",
		class:     ErrInvalidMaterial,
		secondary: ErrInvalidRegistry,
	}
	errVerificationKeyDoesNotMatchCommitment = classifiedError{
		message:   "verification key does not match commitment",
		class:     ErrInvalidMaterial,
		secondary: ErrInvalidRegistry,
	}
	errCommitmentsDoNotMatch = classifiedError{
		message: "public key shares do not have the same commitment",
		class:   ErrInvalidRegistry,
	}
	errPublicKeyDoesNotMatchSecret = classifiedError{
		message: "public key does not match secret key",
		class:   ErrInvalidMaterial,
	}
	errEncodingNonCanonicalPublicKeyShareOrder = classifiedError{
		message:   "encoded public key shares are not in canonical order",
		class:     ErrEncodingFailure,
		secondary: ErrInvalidRegistry,
	}
	errInvalidRegistry         = ErrInvalidRegistry
	errVerifyUnknownID         = ErrUnknownShare
	errNilPubKey               = classifiedError{message: "the provided public key is nil", class: ErrInvalidMaterial}
	errRegistryHasNilPublicKey = classifiedError{
		message:   "encountered a nil public key in registry",
		class:     ErrInvalidRegistry,
		secondary: ErrInvalidMaterial,
	}
	errVerifyBadPubKey = classifiedError{
		message: "the public key differs from the one registered",
		class:   ErrInvalidMaterial,
	}
	errEncodingPKSDuplication = classifiedError{
		message:   "multiple encoded public key shares with same ID",
		class:     ErrEncodingFailure,
		secondary: ErrInvalidRegistry,
	}
	errNilOrInvalid     = classifiedError{message: "nil or invalid", class: ErrInvalidMaterial}
	errGroupNotMatching = classifiedError{message: "group does not match", class: ErrInvalidMaterial}
)
