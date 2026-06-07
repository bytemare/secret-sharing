// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package secretsharing

import (
	"testing"

	"github.com/bytemare/ecc"
)

func TestZeroPolynomialClearsCopiedSecretTerm(t *testing.T) {
	g := ecc.Ristretto255Sha512
	secret := g.NewScalar().Random()

	polynomial, err := makePolynomial(g, secret, 3)
	if err != nil {
		t.Fatal(err)
	}

	coefficients := append(Polynomial(nil), polynomial...)
	if coefficients[0] == secret {
		t.Fatal("polynomial secret coefficient aliases caller secret")
	}

	zeroPolynomial(polynomial)

	if secret.IsZero() {
		t.Fatal("caller secret was cleared")
	}

	for i, coefficient := range coefficients {
		if !coefficient.IsZero() {
			t.Fatalf("coefficient %d was not cleared", i)
		}

		if polynomial[i] != nil {
			t.Fatalf("coefficient %d reference was not removed", i)
		}
	}
}
