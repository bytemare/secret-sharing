// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package secretsharing

import (
	"errors"

	"github.com/bytemare/ecc"
)

var (
	errPolyXIsZero         = errors.New("identifier for interpolation is nil or zero")
	errPolyHasZeroCoeff    = errors.New("one of the polynomial's coefficients is zero")
	errPolyHasDuplicates   = errors.New("the polynomial has duplicate coefficients")
	errPolyHasNilCoeff     = errors.New("the polynomial has a nil coefficient")
	errPolyCoeffInexistant = errors.New("the identifier does not exist in the polynomial")
)

// Polynomial over scalars, represented as a list of t+1 coefficients, where t is the threshold.
// The constant term is in the first position and the highest degree coefficient is in the last position.
// All operations on the polynomial's coefficient are done modulo the scalar's group order.
type Polynomial []*ecc.Scalar

// NewPolynomial returns a slice of Scalars with the capacity to hold the desired coefficients.
func NewPolynomial(coefficients uint16) Polynomial {
	return make(Polynomial, coefficients)
}

// NewPolynomialFromIntegers returns a Polynomial from a slice of uint16.
func NewPolynomialFromIntegers(g ecc.Group, ints []uint16) Polynomial {
	polynomial := make(Polynomial, len(ints))
	for i, v := range ints {
		polynomial[i] = g.NewScalar().SetUInt64(uint64(v))
	}

	return polynomial
}

// NewPolynomialFromListFunc returns a Polynomial from the ecc.Scalar returned by f applied on each element
// of the slice.
func NewPolynomialFromListFunc[S ~[]E, E any](g ecc.Group, s S, f func(E) *ecc.Scalar) Polynomial {
	polynomial := make(Polynomial, len(s))
	for i, v := range s {
		polynomial[i] = g.NewScalar().Set(f(v))
	}

	return polynomial
}

// the only call to copyPolynomial ensure that both polynomials are of the same length.
func copyPolynomial(dst, src Polynomial) error {
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

// Verify returns an appropriate error if the polynomial has a nil or 0 coefficient, or duplicates.
func (p Polynomial) Verify() error {
	if p.hasNil() {
		return errPolyHasNilCoeff
	}

	if p.hasZero() {
		return errPolyHasZeroCoeff
	}

	if p.hasDuplicates() {
		return errPolyHasDuplicates
	}

	return nil
}

// VerifyInterpolatingInput checks compatibility of the input id with the polynomial. If not, an error is returned.
func (p Polynomial) VerifyInterpolatingInput(id *ecc.Scalar) error {
	if id == nil || id.IsZero() {
		return errPolyXIsZero
	}

	if err := p.Verify(); err != nil {
		return err
	}

	if !p.has(id) {
		return errPolyCoeffInexistant
	}

	return nil
}

// Evaluate evaluates the polynomial p at point x using Horner's method.
func (p Polynomial) Evaluate(x *ecc.Scalar) *ecc.Scalar {
	// since value is an accumulator and starts with 0, we can skip multiplying by x, and start from the end
	value := p[len(p)-1].Copy()
	for i := len(p) - 2; i >= 0; i-- {
		value.Multiply(x)
		value.Add(p[i])
	}

	return value
}

// DeriveInterpolatingValue derives a value used for polynomial interpolation.
// id and all the coefficients must be non-zero scalars.
func (p Polynomial) DeriveInterpolatingValue(g ecc.Group, id *ecc.Scalar) (*ecc.Scalar, error) {
	if err := p.VerifyInterpolatingInput(id); err != nil {
		return nil, err
	}

	numerator := g.NewScalar().One()
	denominator := g.NewScalar().One()

	for _, coeff := range p {
		if coeff.Equal(id) {
			continue
		}

		numerator.Multiply(coeff)
		denominator.Multiply(coeff.Copy().Subtract(id))
	}

	return numerator.Multiply(denominator.Invert()), nil
}

// has returns whether s is a coefficient of the polynomial.
func (p Polynomial) has(s *ecc.Scalar) bool {
	for _, si := range p {
		if si.Equal(s) {
			return true
		}
	}

	return false
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
