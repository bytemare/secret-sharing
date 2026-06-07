// SPDX-License-Identifier: MIT
//
// Copyright (C) 2026 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package secretsharing

import "errors"

var (
	// ErrTooFewShares classifies reconstruction inputs that do not provide enough shares.
	ErrTooFewShares = errors.New("number of shares must be equal or greater than the threshold")

	// ErrMalformedCryptoInput classifies malformed cryptographic inputs that trigger fail-closed handling.
	ErrMalformedCryptoInput = errors.New("malformed cryptographic input")

	// ErrInvalidRegistry classifies invalid public share registries used for verified reconstruction.
	ErrInvalidRegistry = errors.New("invalid public key share registry")

	// ErrInvalidMaterial classifies invalid key, share, scalar, or polynomial material.
	ErrInvalidMaterial = errors.New("invalid key/share material")

	// ErrUnknownShare classifies shares that are not present in, or do not match, the public registry.
	ErrUnknownShare = errors.New("key share does not match registry")
)

type classifiedError struct {
	class   error
	message string
}

func (e classifiedError) Error() string {
	return e.message
}

func (e classifiedError) Is(target error) bool {
	return target == e.class
}

var (
	errPolyXIsZero = classifiedError{
		message: "identifier for interpolation is nil or zero",
		class:   ErrInvalidMaterial,
	}
	errPolyHasZeroCoeff = classifiedError{
		message: "one of the polynomial's coefficients is zero",
		class:   ErrInvalidMaterial,
	}
	errPolyHasDuplicates = classifiedError{
		message: "the polynomial has duplicate coefficients",
		class:   ErrInvalidMaterial,
	}
	errPolyHasNilCoeff = classifiedError{
		message: "the polynomial has a nil coefficient",
		class:   ErrInvalidMaterial,
	}
	errPolyCoeffInexistant = classifiedError{
		message: "the identifier does not exist in the polynomial",
		class:   ErrInvalidMaterial,
	}
	errThresholdIsZero = errors.New("threshold is zero")
	errNoShares        = classifiedError{message: "no shares provided", class: ErrTooFewShares}
	errSecretIsZero    = classifiedError{message: "the provided secret is zero", class: ErrInvalidMaterial}
	errTooFewShares    = ErrTooFewShares
	errPolyIsWrongSize = classifiedError{
		message: "invalid number of coefficients in polynomial",
		class:   ErrInvalidMaterial,
	}
	errPolySecretNotSet = classifiedError{
		message: "provided polynomial's first coefficient not set to the secret",
		class:   ErrInvalidMaterial,
	}
	errMultiGroup = classifiedError{
		message: "incompatible EC groups found in set of key shares",
		class:   ErrInvalidMaterial,
	}
	errInvalidGroup         = classifiedError{message: "invalid EC group", class: ErrInvalidMaterial}
	errInvalidScalar        = classifiedError{message: "invalid scalar", class: ErrInvalidMaterial}
	errScalarGroup          = classifiedError{message: "scalar has incompatible EC group", class: ErrInvalidMaterial}
	errNilShare             = classifiedError{message: "key share is nil", class: ErrInvalidMaterial}
	errNilRegistry          = classifiedError{message: "public key share registry is nil", class: ErrInvalidRegistry}
	errInvalidRegistry      = ErrInvalidRegistry
	errInvalidKeyShare      = classifiedError{message: "invalid key share", class: ErrInvalidMaterial}
	errMalformedCrypto      = ErrMalformedCryptoInput
	errShareNotRegistered   = ErrUnknownShare
	errCommitmentNilElement = classifiedError{message: "commitment has nil element", class: ErrInvalidMaterial}
	errCommitmentWrongGroup = classifiedError{
		message: "commitment element has incompatible EC group",
		class:   ErrInvalidMaterial,
	}
	errPolynomialEmpty  = classifiedError{message: "polynomial is empty", class: ErrInvalidMaterial}
	errIdentifierIsZero = classifiedError{message: "identifier is zero", class: ErrInvalidMaterial}
)
