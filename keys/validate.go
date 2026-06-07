// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package keys

import (
	"errors"
	"fmt"
	"math"
	"slices"

	"github.com/bytemare/ecc"
)

const errValidateFMT = "%s: %w"

var (
	errNilOrInvalid     = errors.New("nil or invalid")
	errGroupNotMatching = errors.New("group does not match")
)

func elementGroup(element *ecc.Element) (group ecc.Group, ok bool) {
	if element == nil {
		return 0, false
	}

	defer func() {
		if recover() != nil {
			group = 0
			ok = false
		}
	}()

	group = element.Group()

	return group, group.Available()
}

func scalarGroup(scalar *ecc.Scalar) (group ecc.Group, ok bool) {
	if scalar == nil {
		return 0, false
	}

	defer func() {
		if recover() != nil {
			group = 0
			ok = false
		}
	}()

	group = scalar.Group()

	return group, group.Available()
}

func cloneElement(element *ecc.Element) (cloned *ecc.Element) {
	if _, ok := elementGroup(element); !ok {
		return nil
	}

	defer func() {
		if recover() != nil {
			cloned = nil
		}
	}()

	return element.Copy()
}

func cloneScalar(scalar *ecc.Scalar) (cloned *ecc.Scalar) {
	if _, ok := scalarGroup(scalar); !ok {
		return nil
	}

	defer func() {
		if recover() != nil {
			cloned = nil
		}
	}()

	return scalar.Copy()
}

func validateElement(group ecc.Group, element *ecc.Element, name string) error {
	elementGroup, ok := elementGroup(element)
	if !ok {
		return fmt.Errorf(errValidateFMT, name, errNilOrInvalid)
	}

	if elementGroup != group {
		return fmt.Errorf(errValidateFMT, name, errGroupNotMatching)
	}

	return nil
}

func validateScalar(group ecc.Group, scalar *ecc.Scalar, name string) error {
	scalarGroup, ok := scalarGroup(scalar)
	if !ok {
		return fmt.Errorf(errValidateFMT, name, errNilOrInvalid)
	}

	if scalarGroup != group {
		return fmt.Errorf(errValidateFMT, name, errGroupNotMatching)
	}

	return nil
}

func validatePublicKeyShare(share *PublicKeyShare) error {
	if share == nil {
		return errNilPublicKeyShare
	}

	if !share.group.Available() {
		return errEncodingInvalidGroup
	}

	if share.id == 0 {
		return errInvalidIdentifier
	}

	if err := validateElement(share.group, share.publicKey, "public key"); err != nil {
		return err
	}

	if len(share.vssCommitment) > math.MaxUint16 {
		return errInvalidPolynomialLength
	}

	for i, commitment := range share.vssCommitment {
		if err := validateElement(share.group, commitment, fmt.Sprintf("commitment %d", i+1)); err != nil {
			return err
		}
	}

	if len(share.vssCommitment) != 0 &&
		!publicKeyForCommitment(share.group, share.id, share.vssCommitment).Equal(share.publicKey) {
		return errInvalidVSSShare
	}

	return nil
}

func validateKeyShare(share *KeyShare) error {
	if share == nil {
		return errNilKeyShare
	}

	if err := validatePublicKeyShare(&share.publicKeyShare); err != nil {
		return err
	}

	if err := validateScalar(share.Group(), share.secret, "secret key"); err != nil {
		return err
	}

	if err := validateElement(share.Group(), share.verificationKey, "verification key"); err != nil {
		return err
	}

	expected := share.Group().Base().Multiply(share.secret)
	if !expected.Equal(share.publicKeyShare.publicKey) {
		return errPublicKeyDoesNotMatchSecret
	}

	if len(share.publicKeyShare.vssCommitment) != 0 &&
		!share.verificationKey.Equal(share.publicKeyShare.vssCommitment[0]) {
		return errVerificationKeyDoesNotMatchCommitment
	}

	return nil
}

func publicKeyForCommitment(group ecc.Group, id uint16, commitment []*ecc.Element) *ecc.Element {
	publicKey := commitment[0].Copy()
	x := group.NewScalar().SetUInt64(uint64(id))
	power := group.NewScalar().One()

	for _, coefficient := range commitment[1:] {
		power.Multiply(x)
		publicKey.Add(coefficient.Copy().Multiply(power))
	}

	return publicKey
}

func commitmentsEqual(left, right []*ecc.Element) (equal bool) {
	if len(left) != len(right) {
		return false
	}

	defer func() {
		if recover() != nil {
			equal = false
		}
	}()

	for i := range left {
		leftGroup, leftOK := elementGroup(left[i])
		rightGroup, rightOK := elementGroup(right[i])

		if !leftOK || !rightOK || leftGroup != rightGroup || !left[i].Equal(right[i]) {
			return false
		}
	}

	return true
}

func validateRegistryShare(registry *PublicKeyShareRegistry, share *PublicKeyShare) error {
	if err := validatePublicKeyShare(share); err != nil {
		return err
	}

	if share.id > registry.total {
		return errInvalidIdentifier
	}

	if share.group != registry.group {
		return errEncodingGroupMismatch
	}

	if len(share.vssCommitment) != int(registry.threshold) {
		return errCommitmentLengthDoesNotMatchThreshold
	}

	return nil
}

func validateRegistryParameters(group ecc.Group, threshold, total uint16) error {
	if !group.Available() {
		return errEncodingInvalidGroup
	}

	if total == 0 || threshold == 0 || threshold > total {
		return errInvalidRegistryParameters
	}

	return nil
}

func validateRegistry(registry *PublicKeyShareRegistry, requireComplete bool) error {
	if registry == nil {
		return errNilRegistry
	}

	if err := validateRegistryParameters(registry.group, registry.threshold, registry.total); err != nil {
		return err
	}

	if err := validateElement(registry.group, registry.verificationKey, "verification key"); err != nil {
		return err
	}

	if requireComplete && len(registry.publicKeyShares) != int(registry.total) {
		return errRegistryShareCountDoesNotMatchTotal
	}

	var referenceCommitment []*ecc.Element

	for id, share := range registry.publicKeyShares {
		if share == nil {
			return errNilPublicKeyShare
		}

		if id != share.id {
			return errRegistryMapKeyDoesNotMatchShareID
		}

		if err := validateRegistryShare(registry, share); err != nil {
			return err
		}

		if !share.vssCommitment[0].Equal(registry.verificationKey) {
			return errVerificationKeyDoesNotMatchCommitment
		}

		if referenceCommitment == nil {
			referenceCommitment = share.vssCommitment
		} else if !commitmentsEqual(referenceCommitment, share.vssCommitment) {
			return errCommitmentsDoNotMatch
		}
	}

	return nil
}

func cloneCommitment(commitment []*ecc.Element) []*ecc.Element {
	if commitment == nil {
		return nil
	}

	cloned := make([]*ecc.Element, len(commitment))
	for i, element := range commitment {
		cloned[i] = cloneElement(element)
	}

	return cloned
}

func clonePublicKeyShare(share *PublicKeyShare) *PublicKeyShare {
	if share == nil {
		return nil
	}

	cloned := &PublicKeyShare{
		vssCommitment: cloneCommitment(share.vssCommitment),
		id:            share.id,
		group:         share.group,
	}
	cloned.publicKey = cloneElement(share.publicKey)

	return cloned
}

func sortedShareIDs(shares map[uint16]*PublicKeyShare) []uint16 {
	ids := make([]uint16, 0, len(shares))
	for id := range shares {
		ids = append(ids, id)
	}

	slices.Sort(ids)

	return ids
}
