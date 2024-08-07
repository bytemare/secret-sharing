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
// All operations on the polynomial's coefficient are done modulo the scalar's group order.
type Polynomial []*group.Scalar

// NewPolynomial returns a slice of Scalars with the capacity to hold the desired coefficients.
func NewPolynomial(coefficients uint) Polynomial {
	return make(Polynomial, coefficients)
}

// NewPolynomialFromIntegers returns a Polynomial from a slice of uint64.
func NewPolynomialFromIntegers(g group.Group, ints []uint64) Polynomial {
	polynomial := make(Polynomial, len(ints))
	for i, v := range ints {
		polynomial[i] = g.NewScalar().SetUInt64(v)
	}

	return polynomial
}

// NewPolynomialFromListFunc returns a Polynomial from the uint64 returned by f applied on each element of the slice.
func NewPolynomialFromListFunc[S ~[]E, E any](g group.Group, s S, f func(E) *group.Scalar) Polynomial {
	polynomial := make(Polynomial, len(s))
	for i, v := range s {
		polynomial[i] = g.NewScalar().Set(f(v))
	}

	return polynomial
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

func (p Polynomial) verifyInterpolatingInput(id *group.Scalar) error {
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
func (p Polynomial) Evaluate(x *group.Scalar) *group.Scalar {
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
func PolynomialInterpolateConstant(g group.Group, shares []Share) (*group.Scalar, error) {
	xCoords := NewPolynomialFromListFunc(g, shares, func(share Share) *group.Scalar {
		return g.NewScalar().SetUInt64(share.Identifier())
	})

	key := g.NewScalar().Zero()

	for i, share := range shares {
		iv, err := xCoords.DeriveInterpolatingValue(g, xCoords[i])
		if err != nil {
			return nil, err
		}

		delta := iv.Multiply(share.SecretKey())
		key.Add(delta)
	}

	return key, nil
}
