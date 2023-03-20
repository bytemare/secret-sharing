// SPDX-License-Identifier: MIT
//
// Copyright (C) 2023 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package secretsharing

import (
	"errors"

	group "github.com/bytemare/crypto"
)

var (
	errPolyDiffLength      = errors.New("destination and source polynomials length differ")
	errPolyXIsZero         = errors.New("identifier for interpolation is nil or zero")
	errPolyHasZeroCoeff    = errors.New("one of the polynomial's coefficients is zero")
	errPolyHasDuplicates   = errors.New("the polynomial has duplicate coefficients")
	errPolyHasNilCoeff     = errors.New("the polynomial has a nil coefficient")
	errPolyCoeffInexistant = errors.New("the coefficient does not exist in the polynomial")
)

// Polynomial over scalars, represented as a list of t+1 coefficients, where t is the threshold.
// The constant term is in the first position and the highest degree coefficient is in the last position.
type Polynomial []*group.Scalar

// NewPolynomial returns a slice of Scalars with the capacity to hold the desired coefficients.
func NewPolynomial(coefficients uint) Polynomial {
	return make(Polynomial, coefficients)
}

func copyPolynomial(dst, src Polynomial) error {
	if len(dst) != len(src) {
		return errPolyDiffLength
	}

	for index, coeff := range src {
		if coeff == nil {
			return errPolyHasNilCoeff
		}

		if coeff.IsZero() {
			return errPolyHasZeroCoeff
		}

		dst[index] = coeff.Copy()
	}

	return nil
}

func (p Polynomial) verifyInterpolatingInput(id *group.Scalar) error {
	if id == nil || id.IsZero() {
		return errPolyXIsZero
	}

	if p.hasNil() {
		return errPolyHasNilCoeff
	}

	if p.hasZero() {
		return errPolyHasZeroCoeff
	}

	if !p.has(id) {
		return errPolyCoeffInexistant
	}

	if p.hasDuplicates() {
		return errPolyHasDuplicates
	}

	return nil
}

// has returns whether s is a coefficient of the polynomial.
func (p Polynomial) hasNil() bool {
	for _, si := range p {
		if si == nil {
			return true
		}
	}

	return false
}

// has returns whether s is a coefficient of the polynomial.
func (p Polynomial) has(s *group.Scalar) bool {
	for _, si := range p {
		if si.Equal(s) == 1 {
			return true
		}
	}

	return false
}

// hasZero returns whether one of the polynomials coefficients is 0.
func (p Polynomial) hasZero() bool {
	for _, xj := range p {
		if xj.IsZero() {
			return true
		}
	}

	return false
}

// hasDuplicates returns whether the polynomial has at least one coefficient that appears more than once.
func (p Polynomial) hasDuplicates() bool {
	visited := make(map[string]bool, len(p))

	for _, pi := range p {
		enc := string(pi.Encode())
		if visited[enc] {
			return true
		}

		visited[enc] = true
	}

	return false
}

// Evaluate evaluates the polynomial p at point x using Horner's method.
func (p Polynomial) Evaluate(g group.Group, x *group.Scalar) *group.Scalar {
	value := g.NewScalar().Zero().Add(p[len(p)-1]) // since value starts with 0, we can skip multiplying by x
	for i := len(p) - 2; i >= 0; i-- {
		value.Multiply(x)
		value.Add(p[i])
	}

	return value
}

// DeriveInterpolatingValue derives a value used for polynomial interpolation.
// id and all the coefficients must be non-zero scalars.
func (p Polynomial) DeriveInterpolatingValue(g group.Group, id *group.Scalar) (*group.Scalar, error) {
	if err := p.verifyInterpolatingInput(id); err != nil {
		return nil, err
	}

	numerator := g.NewScalar().One()
	denominator := g.NewScalar().One()

	for _, coeff := range p {
		if coeff.Equal(id) == 1 {
			continue
		}

		numerator.Multiply(coeff)
		denominator.Multiply(coeff.Copy().Subtract(id))
	}

	return numerator.Multiply(denominator.Invert()), nil
}

// PolynomialInterpolateConstant recovers the constant term of the interpolating polynomial defined by the set of
// key shares.
func PolynomialInterpolateConstant(g group.Group, shares []*KeyShare) (*group.Scalar, error) {
	xCoords := make(Polynomial, len(shares))
	for i, share := range shares {
		xCoords[i] = share.Identifier
	}

	constant := g.NewScalar().Zero()

	for _, share := range shares {
		iv, err := xCoords.DeriveInterpolatingValue(g, share.Identifier)
		if err != nil {
			return nil, err
		}

		delta := share.SecretKey.Copy().Multiply(iv)
		constant.Add(delta)
	}

	return constant, nil
}
