// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package secretsharing_test

import (
	"encoding/json"
	"fmt"
	"strings"
)

func testDecodingBytesNilEmpty(decoder serde, expectedError string) error {
	// nil input
	if err := decoder.Decode(nil); err == nil || err.Error() != expectedError {
		return fmt.Errorf("expected error %q, got %q", expectedError, err)
	}

	// empty input
	if err := decoder.Decode([]byte{}); err == nil || err.Error() != expectedError {
		return fmt.Errorf("expected error %q, got %q", expectedError, err)
	}

	return nil
}

func testDecodeBytesBadCiphersuite(decoder serde, headerLength int, expectedError string) error {
	input := make([]byte, headerLength)
	input[0] = 2

	if err := decoder.Decode(input); err == nil || err.Error() != expectedError {
		return fmt.Errorf("expected error %q, got %q", expectedError, err)
	}

	return nil
}

func testDecodeHexOddLength(encoder, decoder serde, expectedError string) error {
	h := encoder.Hex()
	if err := decoder.DecodeHex(h[:len(h)-1]); err == nil || err.Error() != expectedError {
		return fmt.Errorf("expected error %q, got %q", expectedError, err)
	}

	return nil
}

type jsonTesterBaddie struct {
	key, value, expectedError string
}

func testJSONBaddie(in any, decoded json.Unmarshaler, baddie jsonTesterBaddie) error {
	data, err := json.Marshal(in)
	if err != nil {
		return err
	}

	data = replaceStringInBytes(data, baddie.key, baddie.value)

	err = json.Unmarshal(data, decoded)

	if len(baddie.expectedError) != 0 { // we're expecting an error
		if err == nil ||
			!strings.HasPrefix(err.Error(), baddie.expectedError) {
			return fmt.Errorf("expected error %q, got %q", baddie.expectedError, err)
		}
	} else {
		if err != nil {
			return fmt.Errorf("unexpected error %q", err)
		}
	}

	return nil
}

func jsonTester(errPrefix, badJSONErr string, in any, decoded json.Unmarshaler, baddies ...jsonTesterBaddie) error {
	errInvalidCiphersuite := errPrefix + ": invalid group identifier"

	// JSON: bad json
	baddie := jsonTesterBaddie{
		key:           "\"group\"",
		value:         "bad",
		expectedError: "invalid character 'b' looking for beginning of object key string",
	}

	if err := testJSONBaddie(in, decoded, baddie); err != nil {
		return err
	}

	// UnmarshallJSON: bad group
	baddie = jsonTesterBaddie{
		key:           "\"group\"",
		value:         "\"group\":2, \"oldGroup\"",
		expectedError: errInvalidCiphersuite,
	}

	if err := testJSONBaddie(in, decoded, baddie); err != nil {
		return err
	}

	// UnmarshallJSON: bad ciphersuite
	baddie = jsonTesterBaddie{
		key:           "\"group\"",
		value:         "\"group\":70, \"oldGroup\"",
		expectedError: errInvalidCiphersuite,
	}

	if err := testJSONBaddie(in, decoded, baddie); err != nil {
		return err
	}

	// UnmarshallJSON: bad ciphersuite
	baddie = jsonTesterBaddie{
		key:           "\"group\"",
		value:         "\"group\":-1, \"oldGroup\"",
		expectedError: badJSONErr,
	}

	if err := testJSONBaddie(in, decoded, baddie); err != nil {
		return err
	}

	// UnmarshallJSON: bad ciphersuite
	overflow := "9223372036854775808" // MaxInt64 + 1
	baddie = jsonTesterBaddie{
		key:           "\"group\"",
		value:         "\"group\":" + overflow + ", \"oldGroup\"",
		expectedError: errPrefix + ": failed to read Group: strconv.Atoi: parsing \"9223372036854775808\": value out of range",
	}

	if err := testJSONBaddie(in, decoded, baddie); err != nil {
		return err
	}

	// Replace keys and values
	for _, baddie = range baddies {
		if err := testJSONBaddie(in, decoded, baddie); err != nil {
			return err
		}
	}

	return nil
}
