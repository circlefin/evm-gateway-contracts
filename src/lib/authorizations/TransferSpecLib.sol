/**
 * Copyright 2025 Circle Internet Group, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
pragma solidity ^0.8.29;

import {TypedMemView} from "@memview-sol/TypedMemView.sol";
import {
    TransferSpec,
    TRANSFER_SPEC_MAGIC,
    TRANSFER_SPEC_VERSION,
    TRANSFER_SPEC_VERSION_OFFSET,
    TRANSFER_SPEC_SOURCE_DOMAIN_OFFSET,
    TRANSFER_SPEC_DESTINATION_DOMAIN_OFFSET,
    TRANSFER_SPEC_SOURCE_CONTRACT_OFFSET,
    TRANSFER_SPEC_DESTINATION_CONTRACT_OFFSET,
    TRANSFER_SPEC_SOURCE_TOKEN_OFFSET,
    TRANSFER_SPEC_DESTINATION_TOKEN_OFFSET,
    TRANSFER_SPEC_SOURCE_DEPOSITOR_OFFSET,
    TRANSFER_SPEC_DESTINATION_RECIPIENT_OFFSET,
    TRANSFER_SPEC_SOURCE_SIGNER_OFFSET,
    TRANSFER_SPEC_DESTINATION_CALLER_OFFSET,
    TRANSFER_SPEC_VALUE_OFFSET,
    TRANSFER_SPEC_NONCE_OFFSET,
    TRANSFER_SPEC_METADATA_LENGTH_OFFSET,
    TRANSFER_SPEC_METADATA_OFFSET,
    // solhint-disable-next-line no-unused-import
    TRANSFER_SPEC_TYPEHASH
} from "./TransferSpec.sol";

uint8 constant BYTES4_BYTES = 4;
uint8 constant UINT32_BYTES = 4;
uint8 constant UINT256_BYTES = 32;
uint8 constant BYTES32_BYTES = 32;

/// @title TransferSpecLib
///
/// @notice Library for encoding, validating, hashing, and providing field accessors for `TransferSpec` structs
///
/// @dev Provides low-level access and manipulation functions for byte-encoded `TransferSpec` data, using `TypedMemView`
///      for efficient memory operations
library TransferSpecLib {
    using TypedMemView for bytes;
    using TypedMemView for bytes29;

    // --- TransferSpec errors -----------------------------------------------------------------------------------------

    /// Thrown when casting data as a `TransferSpec` and the input is shorter than the expected magic length
    ///
    /// @param expectedMinimumLength   The expected minimum length of the data
    /// @param actualLength            The actual length of the data
    error TransferSpecDataTooShort(uint256 expectedMinimumLength, uint256 actualLength);

    /// Thrown when casting data as a `TransferSpec` and the magic value is not the expected value
    ///
    /// @param actualMagic   The magic value found in the data
    error InvalidTransferSpecMagic(bytes4 actualMagic);

    /// Thrown when validating an encoded `TransferSpec` and the header is shorter than expected
    ///
    /// @param expectedMinimumLength   The expected minimum length of the header
    /// @param actualLength            The actual length of the header
    error TransferSpecHeaderTooShort(uint256 expectedMinimumLength, uint256 actualLength);

    /// Thrown when validating an encoded `TransferSpec` and the version is not the expected value
    ///
    /// @param actualVersion   The version found in the data
    error InvalidTransferSpecVersion(uint32 actualVersion);

    /// Thrown when validating an encoded `TransferSpec` and the length of the data is different than what is implied by
    /// the metadata length
    ///
    /// @param expectedTotalLength   The expected length of the data
    /// @param actualTotalLength     The actual length of the data
    error TransferSpecOverallLengthMismatch(uint256 expectedTotalLength, uint256 actualTotalLength);

    /// Thrown when encoding a `TransferSpec` and the metadata length exceeds the maximum encodable length
    ///
    /// @param actualLength   The actual length of the metadata
    /// @param maxLength      The maximum encodable length of the metadata
    error TransferSpecMetadataFieldTooLarge(uint256 actualLength, uint256 maxLength);

    /// Thrown when the metadata view matches the NULL value from `TypedMemView`
    ///
    /// @param expectedMetadataLength   The expected metadata length declared in the metadata length field
    /// @param transferSpecLength       The length of the transfer spec
    error TransferSpecInvalidMetadata(uint256 expectedMetadataLength, uint256 transferSpecLength);

    // --- Common Authorization errors ---------------------------------------------------------------------------------

    /// Thrown when casting data as an authorization or authorization set and the input is shorter than the expected
    /// magic length
    ///
    /// @param expectedMinimumLength   The expected minimum length of the data
    /// @param actualLength            The actual length of the data
    error AuthorizationDataTooShort(uint256 expectedMinimumLength, uint256 actualLength);

    /// Thrown when casting data as an authorization or authorization set and the magic value is not an expected value
    ///
    /// @param actualMagic   The magic value found in the data
    error InvalidAuthorizationMagic(bytes4 actualMagic);

    /// Thrown when validating an encoded authorization and the header is shorter than expected
    ///
    /// @param expectedMinimumLength   The expected minimum length of the header
    /// @param actualLength            The actual length of the header
    error AuthorizationHeaderTooShort(uint256 expectedMinimumLength, uint256 actualLength);

    /// Thrown when validating an encoded authorization and the length of the data is different than what is implied by
    /// the embedded `TransferSpec`
    ///
    /// @param expectedTotalLength   The expected length of the data
    /// @param actualTotalLength     The actual length of the data
    error AuthorizationOverallLengthMismatch(uint256 expectedTotalLength, uint256 actualTotalLength);

    // --- Common AuthorizationSet errors ------------------------------------------------------------------------------

    /// Thrown when validating an encoded authorization set and the set header is shorter than expected
    ///
    /// @param expectedMinimumLength   The expected minimum length of the header
    /// @param actualLength            The actual length of the header
    error AuthorizationSetHeaderTooShort(uint256 expectedMinimumLength, uint256 actualLength);

    /// Thrown when validating an encoded authorization set and one of the elements' header is shorter than expected
    ///
    /// @param index             The index of the element with the issue
    /// @param actualSetLength   The actual length of the encoded set
    /// @param requiredOffset    The expected offset of the element header
    error AuthorizationSetElementHeaderTooShort(uint32 index, uint256 actualSetLength, uint256 requiredOffset);

    /// Thrown when validating an encoded authorization set and one of the elements is shorter than expected
    ///
    /// @param index             The index of the element with the issue
    /// @param actualSetLength   The actual length of the encoded set
    /// @param requiredOffset    The expected offset of the element header
    error AuthorizationSetElementTooShort(uint32 index, uint256 actualSetLength, uint256 requiredOffset);

    /// Thrown when validating an encoded authorization set and one of the elements has an unexpected magic value
    ///
    /// @param index         The index of the element with the issue
    /// @param actualMagic   The magic value found in the element
    error AuthorizationSetInvalidElementMagic(uint32 index, bytes4 actualMagic);

    /// Thrown when validating an encoded authorization set and the length of the data is different than what is implied
    /// by the authorizations themselves
    ///
    /// @param expectedTotalLength   The expected length of the data
    /// @param actualTotalLength     The actual length of the data
    error AuthorizationSetOverallLengthMismatch(uint256 expectedTotalLength, uint256 actualTotalLength);

    /// Thrown when encoding an authorization set and the number of elements exceeds the maximum encodable value
    ///
    /// @param maxElements   The maximum number of elements that is possible to encode
    error AuthorizationSetTooManyElements(uint32 maxElements);

    // --- Common iteration errors -------------------------------------------------------------------------------------

    /// Thrown when iterating over an authorization or authorization set and `next()` is called on a cursor that is
    /// already `done`
    error CursorOutOfBounds();

    // --- Common utilities --------------------------------------------------------------------------------------------

    /// Converts a magic value from the byte encoding to a `TypedMemView` type
    ///
    /// @param magic   The magic value to convert
    /// @return        The `TypedMemView` type for the magic value
    function _toMemViewType(bytes4 magic) internal pure returns (uint40) {
        return uint40(uint32(magic));
    }

    // --- Validation --------------------------------------------------------------------------------------------------

    /// Validates the structural integrity of an encoded `TransferSpec` memory view
    ///
    /// @notice Validation steps:
    ///   1. Minimum header length check
    ///   2. Version check
    ///   3. Total length consistency check (using declared `TransferSpec` length)
    ///
    /// @dev Performs structural validation on a `TransferSpec` view. Reverts on failure. Assumes outer magic number
    ///      check has passed (via casting).
    ///
    /// @param specView   The `TypedMemView` reference to the encoded `TransferSpec` to validate
    function _validateTransferSpecStructure(bytes29 specView) internal pure {
        // 1. Minimum header length check
        if (specView.len() < TRANSFER_SPEC_METADATA_OFFSET) {
            revert TransferSpecHeaderTooShort(TRANSFER_SPEC_METADATA_OFFSET, specView.len());
        }

        // 2. Version check
        uint32 version = getVersion(specView);
        if (version != TRANSFER_SPEC_VERSION) {
            revert InvalidTransferSpecVersion(version);
        }

        // 3. Total length consistency check
        //    (Reads declared metadata length from the view and checks against view's total length)
        uint32 metadataLength = getMetadataLength(specView);
        uint256 expectedInternalSpecLength = TRANSFER_SPEC_METADATA_OFFSET + metadataLength;
        if (specView.len() != expectedInternalSpecLength) {
            revert TransferSpecOverallLengthMismatch(expectedInternalSpecLength, specView.len());
        }
    }

    // --- Field accessors ---------------------------------------------------------------------------------------------

    /// Extract the version from an encoded `TransferSpec`
    ///
    /// @param ref   The `TypedMemView` reference to the encoded `TransferSpec`
    /// @return      The `version` field
    function getVersion(bytes29 ref) internal pure returns (uint32) {
        return uint32(ref.indexUint(TRANSFER_SPEC_VERSION_OFFSET, UINT32_BYTES));
    }

    /// Extract the source domain from an encoded `TransferSpec`
    ///
    /// @param ref   The `TypedMemView` reference to the encoded `TransferSpec`
    /// @return      The `sourceDomain` field
    function getSourceDomain(bytes29 ref) internal pure returns (uint32) {
        return uint32(ref.indexUint(TRANSFER_SPEC_SOURCE_DOMAIN_OFFSET, UINT32_BYTES));
    }

    /// Extract the destination domain from an encoded `TransferSpec`
    ///
    /// @param ref   The `TypedMemView` reference to the encoded `TransferSpec`
    /// @return      The `destinationDomain` field
    function getDestinationDomain(bytes29 ref) internal pure returns (uint32) {
        return uint32(ref.indexUint(TRANSFER_SPEC_DESTINATION_DOMAIN_OFFSET, UINT32_BYTES));
    }

    /// Extract the source contract from an encoded `TransferSpec`
    ///
    /// @param ref   The `TypedMemView` reference to the encoded `TransferSpec`
    /// @return      The `sourceContract` field
    function getSourceContract(bytes29 ref) internal pure returns (bytes32) {
        return ref.index(TRANSFER_SPEC_SOURCE_CONTRACT_OFFSET, BYTES32_BYTES);
    }

    /// Extract the destination contract from an encoded `TransferSpec`
    ///
    /// @param ref   The `TypedMemView` reference to the encoded `TransferSpec`
    /// @return      The `destinationContract` field
    function getDestinationContract(bytes29 ref) internal pure returns (bytes32) {
        return ref.index(TRANSFER_SPEC_DESTINATION_CONTRACT_OFFSET, BYTES32_BYTES);
    }

    /// Extract the source token from an encoded `TransferSpec`
    ///
    /// @param ref   The `TypedMemView` reference to the encoded `TransferSpec`
    /// @return      The `sourceToken` field
    function getSourceToken(bytes29 ref) internal pure returns (bytes32) {
        return ref.index(TRANSFER_SPEC_SOURCE_TOKEN_OFFSET, BYTES32_BYTES);
    }

    /// Extract the destination token from an encoded `TransferSpec`
    ///
    /// @param ref   The `TypedMemView` reference to the encoded `TransferSpec`
    /// @return      The `destinationToken` field
    function getDestinationToken(bytes29 ref) internal pure returns (bytes32) {
        return ref.index(TRANSFER_SPEC_DESTINATION_TOKEN_OFFSET, BYTES32_BYTES);
    }

    /// Extract the source depositor from an encoded `TransferSpec`
    ///
    /// @param ref   The `TypedMemView` reference to the encoded `TransferSpec`
    /// @return      The `sourceDepositor` field
    function getSourceDepositor(bytes29 ref) internal pure returns (bytes32) {
        return ref.index(TRANSFER_SPEC_SOURCE_DEPOSITOR_OFFSET, BYTES32_BYTES);
    }

    /// Extract the destination recipient from an encoded `TransferSpec`
    ///
    /// @param ref   The `TypedMemView` reference to the encoded `TransferSpec`
    /// @return      The `destinationRecipient` field
    function getDestinationRecipient(bytes29 ref) internal pure returns (bytes32) {
        return ref.index(TRANSFER_SPEC_DESTINATION_RECIPIENT_OFFSET, BYTES32_BYTES);
    }

    /// Extract the source signer from an encoded `TransferSpec`
    ///
    /// @param ref   The `TypedMemView` reference to the encoded `TransferSpec`
    /// @return      The `sourceSigner` field
    function getSourceSigner(bytes29 ref) internal pure returns (bytes32) {
        return ref.index(TRANSFER_SPEC_SOURCE_SIGNER_OFFSET, BYTES32_BYTES);
    }

    /// Extract the destination caller from an encoded `TransferSpec`
    ///
    /// @param ref   The `TypedMemView` reference to the encoded `TransferSpec`
    /// @return      The `destinationCaller` field
    function getDestinationCaller(bytes29 ref) internal pure returns (bytes32) {
        return ref.index(TRANSFER_SPEC_DESTINATION_CALLER_OFFSET, BYTES32_BYTES);
    }

    /// Extract the value from an encoded `TransferSpec`
    ///
    /// @param ref   The `TypedMemView` reference to the encoded `TransferSpec`
    /// @return      The `value` field
    function getValue(bytes29 ref) internal pure returns (uint256) {
        return ref.indexUint(TRANSFER_SPEC_VALUE_OFFSET, UINT256_BYTES);
    }

    /// Extract the nonce from an encoded `TransferSpec`
    ///
    /// @param ref   The `TypedMemView` reference to the encoded `TransferSpec`
    /// @return      The `nonce` field
    function getNonce(bytes29 ref) internal pure returns (bytes32) {
        return ref.index(TRANSFER_SPEC_NONCE_OFFSET, BYTES32_BYTES);
    }

    /// Extract the metadata length from an encoded `TransferSpec`
    ///
    /// @param ref   The `TypedMemView` reference to the encoded `TransferSpec`
    /// @return      The `metadata` length
    function getMetadataLength(bytes29 ref) internal pure returns (uint32) {
        return uint32(ref.indexUint(TRANSFER_SPEC_METADATA_LENGTH_OFFSET, UINT32_BYTES));
    }

    /// Extract the metadata from an encoded `TransferSpec` as a memory view
    ///
    /// @param ref   The `TypedMemView` reference to the encoded `TransferSpec`
    /// @return      The metadata as a `TypedMemView` reference
    function getMetadata(bytes29 ref) internal pure returns (bytes29) {
        uint32 metadataLength = getMetadataLength(ref);
        bytes29 metadataView;
        if (metadataLength > 0) {
            metadataView = ref.slice(TRANSFER_SPEC_METADATA_OFFSET, metadataLength, 0);
        } else {
            // Return an empty slice
            metadataView = ref.slice(TRANSFER_SPEC_METADATA_OFFSET, 0, 0);
        }

        // Sanity check that the metadata view is valid. A NULL view would indicate that the
        // actual metadata length differs from the declared length in the metadata length field
        // or extends beyond the bounds of the transfer spec data.
        if (metadataView == TypedMemView.NULL) {
            revert TransferSpecInvalidMetadata(metadataLength, ref.len());
        }

        return metadataView;
    }

    // --- Encoding ----------------------------------------------------------------------------------------------------

    /// Encode a TransferSpec struct into bytes
    ///
    /// @dev Encoding is split into two parts to avoid "stack too deep" errors
    ///
    /// @param spec   The `TransferSpec` to encode
    /// @return       The encoded bytes
    function encodeTransferSpec(TransferSpec memory spec) internal pure returns (bytes memory) {
        bytes memory header = _encodeTransferSpecHeader(
            spec.version,
            spec.sourceDomain,
            spec.destinationDomain,
            spec.sourceContract,
            spec.destinationContract,
            spec.sourceToken,
            spec.destinationToken,
            spec.sourceDepositor
        );
        bytes memory footer = _encodeTransferSpecFooter(
            spec.destinationRecipient, spec.sourceSigner, spec.destinationCaller, spec.value, spec.nonce, spec.metadata
        );
        return bytes.concat(header, footer);
    }

    /// Encode the first part of a `TransferSpec` struct into bytes
    ///
    /// @dev Encoding is split into two parts to avoid "stack too deep" errors
    ///
    /// @param version               The `version` field
    /// @param sourceDomain          The `sourceDomain` field
    /// @param destinationDomain     The `destinationDomain` field
    /// @param sourceContract        The `sourceContract` field
    /// @param destinationContract   The `destinationContract` field
    /// @param sourceToken           The `sourceToken` field
    /// @param destinationToken      The `destinationToken` field
    /// @param sourceDepositor       The `sourceDepositor` field
    /// @return                      The encoded bytes
    function _encodeTransferSpecHeader(
        uint32 version,
        uint32 sourceDomain,
        uint32 destinationDomain,
        bytes32 sourceContract,
        bytes32 destinationContract,
        bytes32 sourceToken,
        bytes32 destinationToken,
        bytes32 sourceDepositor
    ) private pure returns (bytes memory) {
        return abi.encodePacked(
            TRANSFER_SPEC_MAGIC,
            version,
            sourceDomain,
            destinationDomain,
            sourceContract,
            destinationContract,
            sourceToken,
            destinationToken,
            sourceDepositor
        );
    }

    /// Encode the last part of a `TransferSpec` struct into bytes
    ///
    /// @dev Encoding is split into two parts to avoid "stack too deep" errors
    ///
    /// @param destinationRecipient   The `destinationRecipient` field
    /// @param sourceSigner           The `sourceSigner` field
    /// @param destinationCaller      The `destinationCaller` field
    /// @param value                  The `value` field
    /// @param nonce                  The `nonce` field
    /// @param metadata               The `metadata` field
    /// @return                       The encoded bytes
    function _encodeTransferSpecFooter(
        bytes32 destinationRecipient,
        bytes32 sourceSigner,
        bytes32 destinationCaller,
        uint256 value,
        bytes32 nonce,
        bytes memory metadata
    ) private pure returns (bytes memory) {
        if (metadata.length > type(uint32).max) {
            revert TransferSpecMetadataFieldTooLarge(metadata.length, type(uint32).max);
        }

        return abi.encodePacked(
            destinationRecipient,
            sourceSigner,
            destinationCaller,
            value,
            nonce,
            uint32(metadata.length), // 4 bytes
            metadata
        );
    }

    // --- Hashing -----------------------------------------------------------------------------------------------------

    /// Calculate the `keccak256` hash of a `TransferSpec` view
    ///
    /// @param ref   The `TypedMemView` reference to the encoded `TransferSpec`
    /// @return      The `keccak256` hash of the encoded `TransferSpec` bytes
    function getHash(bytes29 ref) internal pure returns (bytes32) {
        return ref.keccak();
    }

    /// Calculate the `keccak256` hash of a `TransferSpec` view formatted for EIP-712 signing
    ///
    /// @dev This function formats the hash according to EIP-712 typed data signing standard.
    ///      The resulting hash can be used with `eth_signTypedData` for secure message signing.
    ///      The hash includes all fields of the TransferSpec struct in a structured format.
    ///
    /// @param spec         The `TypedMemView` reference to the encoded `TransferSpec`
    /// @return structHash  The EIP-712 formatted hash of the TransferSpec for signing
    function getTypedDataHash(bytes29 spec) internal view returns (bytes32 structHash) {
        uint32 version = getVersion(spec);
        uint32 sourceDomain = getSourceDomain(spec);
        uint32 destinationDomain = getDestinationDomain(spec);
        bytes32 metadataHash = getMetadata(spec).keccak();

        uint96 footerStart = uint96(TRANSFER_SPEC_SOURCE_CONTRACT_OFFSET) + spec.loc();
        uint96 footerLen = uint96(BYTES32_BYTES) * 10;

        assembly {
            // Get the free memory pointer
            let ptr := mload(0x40)

            // Store the type hash at 0x00 (first 32 bytes)
            mstore(ptr, TRANSFER_SPEC_TYPEHASH)

            // Store version at 0x20 (32-64 bytes)
            mstore(add(ptr, 32), version)

            // Store sourceDomain at 0x40 (64-96 bytes)
            mstore(add(ptr, 64), sourceDomain)

            // Store destinationDomain at 0x60 (96-128 bytes)
            mstore(add(ptr, 96), destinationDomain)

            // Copy 320 bytes (10 x 32 bytes) from footerStart to ptr+128 using staticcall
            // This efficiently copies the following TransferSpec fields in order:
            // - sourceContract      (32 bytes) -> offset 128-160
            // - destinationContract (32 bytes) -> offset 160-192
            // - sourceToken         (32 bytes) -> offset 192-224
            // - destinationToken    (32 bytes) -> offset 224-256
            // - sourceDepositor     (32 bytes) -> offset 256-288
            // - destinationRecipient(32 bytes) -> offset 288-320
            // - sourceSigner        (32 bytes) -> offset 320-352
            // - destinationCaller   (32 bytes) -> offset 352-384
            // - value               (32 bytes) -> offset 384-416
            // - nonce               (32 bytes) -> offset 416-448
            //
            // Uses staticcall to memory address 4 (identity precompile) which efficiently
            // copies memory regions. This is more gas efficient than copying each field individually.
            // The pop() removes the success boolean returned by staticcall since we don't need it.
            pop(staticcall(gas(), 4, footerStart, footerLen, add(ptr, 128), footerLen))

            // Store metadataHash at 0x1C0 (448-480 bytes)
            mstore(add(ptr, 448), metadataHash)

            // Compute keccak256 hash of the entire struct (480 bytes total)
            structHash := keccak256(ptr, 480)
        }
    }
}
