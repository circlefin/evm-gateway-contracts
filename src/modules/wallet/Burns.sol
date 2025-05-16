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

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {GatewayCommon} from "src/GatewayCommon.sol";
import {IBurnToken} from "src/interfaces/IBurnToken.sol";
import {Cursor} from "src/lib/Cursor.sol";
import {BurnIntentLib} from "src/lib/BurnIntentLib.sol";
import {BurnIntent, BurnIntentSet} from "src/lib/BurnIntents.sol";
import {TransferSpecLib} from "src/lib/TransferSpecLib.sol";
import {AddressLib} from "src/lib/AddressLib.sol";
import {EIP712Domain} from "src/lib/EIP712Domain.sol";
import {Balances} from "src/modules/wallet/Balances.sol";
import {Delegation} from "src/modules/wallet/Delegation.sol";

/// @title Burns
///
/// @notice Manages burns for the `GatewayWallet` contract
contract Burns is GatewayCommon, Balances, Delegation, EIP712Domain {
    using TransferSpecLib for bytes29;
    using BurnIntentLib for bytes29;
    using BurnIntentLib for Cursor;
    using MessageHashUtils for bytes32;
    using SafeERC20 for IERC20;

    /// Emitted when the operator burns tokens that have been minted on another domain
    ///
    /// @param token                  The token that was burned
    /// @param depositor              The depositor who owned the balance
    /// @param transferSpecHash       The `keccak256` hash of the `TransferSpec`
    /// @param destinationDomain      The domain the corresponding mint authorization was used on
    /// @param destinationRecipient   The recipient of the funds at the destination
    /// @param signer                 The address that authorized the transfer
    /// @param value                  The value that was burned
    /// @param fee                    The fee charged for the burn
    /// @param fromAvailable          The value burned from the `available` balance
    /// @param fromWithdrawing        The value burned from the `withdrawing` balance
    event GatewayBurned(
        address indexed token,
        address indexed depositor,
        bytes32 indexed transferSpecHash,
        uint32 destinationDomain,
        bytes32 destinationRecipient,
        address signer,
        uint256 value,
        uint256 fee,
        uint256 fromAvailable,
        uint256 fromWithdrawing
    );

    /// Emitted when the depositor does not have a sufficient balance to cover what needs to be burned. This should
    /// never happen under normal circumstances.
    ///
    /// @param token                The token being burned
    /// @param depositor            The depositor who owns the balance
    /// @param value                The amount that needed to be burned
    /// @param availableBalance     The amount that was present in the `available` balance
    /// @param withdrawingBalance   The amount that was present in the `withdrawing` balance
    event InsufficientBalance(
        address indexed token,
        address indexed depositor,
        uint256 value,
        uint256 availableBalance,
        uint256 withdrawingBalance
    );

    /// Emitted when the `burnSigner` role is updated
    ///
    /// @param oldBurnSigner   The previous burn signer address
    /// @param newBurnSigner   The new burn signer address
    event BurnSignerUpdated(address oldBurnSigner, address newBurnSigner);

    /// Emitted when the `feeRecipient` role is updated
    ///
    /// @param oldFeeRecipient   The previous fee recipient address
    /// @param newFeeRecipient   The new fee recipient address
    event FeeRecipientUpdated(address oldFeeRecipient, address newFeeRecipient);

    /// Thrown when a burn intent set or batch is empty
    error MustHaveAtLeastOneBurnIntent();

    /// Thrown when there is a mismatch between burn intents, signatures, or fees
    error MismatchedBurn();

    /// Thrown when burn intents in a set are not all for the same token
    error NotAllSameToken();

    /// Thrown when the calldata for `gatewayBurn` is not signed by the `burnSigner`
    error InvalidBurnSigner();

    /// Thrown when there are no burn intents that are relevant to the current domain
    error NoRelevantBurnIntents();

    /// Thrown when a burn intent's value is zero
    ///
    /// @param index   The index of the burn intent with the issue
    error AuthorizationValueMustBePositiveAtIndex(uint32 index);

    /// Thrown when a burn intent is expired
    ///
    /// @param index            The index of the burn intent with the issue
    /// @param maxBlockHeight   The burn intent's expiration block height
    /// @param currentBlock     The current block height
    error AuthorizationExpiredAtIndex(uint32 index, uint256 maxBlockHeight, uint256 currentBlock);

    /// Thrown when the fee charged for a burn is too high
    ///
    /// @param index       The index of the burn intent with the issue
    /// @param maxFee      The maximum fee that was allowed by the source signer
    /// @param actualFee   The fee that the operator attempted to charge
    error BurnFeeTooHighAtIndex(uint32 index, uint256 maxFee, uint256 actualFee);

    /// Thrown when a burn intent has the wrong source contract
    ///
    /// @param index              The index of the burn intent with the issue
    /// @param authContract       The source contract from the burn intent
    /// @param expectedContract   The address of this contract
    error InvalidAuthorizationSourceContractAtIndex(uint32 index, address authContract, address expectedContract);

    /// Thrown when the source token in a burn intent is not supported
    ///
    /// @param index         The index of the burn intent with the issue
    /// @param sourceToken   The source token from the burn intent
    error UnsupportedTokenAtIndex(uint32 index, address sourceToken);

    /// Thrown when a burn intent is not signed by the burn signer specified in the `TransferSpec`
    ///
    /// @param index          The index of the burn intent with the issue
    /// @param authSigner     The source signer from the burn intent
    /// @param actualSigner   The signer that was recovered from the signature
    error InvalidAuthorizationSourceSignerAtIndex(uint32 index, address authSigner, address actualSigner);

    /// Initializes the `burnSigner` and `feeRecipient` roles
    ///
    /// @param burnSigner_     The address to initialize the `burnSigner` role
    /// @param feeRecipient_   The address to initialize the `feeRecipient` role
    function __Burns_init(address burnSigner_, address feeRecipient_) internal onlyInitializing {
        updateBurnSigner(burnSigner_);
        updateFeeRecipient(feeRecipient_);
    }

    /// Called by the operator to debit the depositor's balance and burn tokens after an equivalent amount was minted on
    /// another chain. Charges a fee for the burn (which may be at most each burn intent's `maxFee`), and sends
    /// it to the `feeRecipient`.
    ///
    /// @dev The `calldataBytes` input must be ABI-encoded and contain three arrays: `authorizations`, `signatures`,
    ///      and `fees`.
    /// @dev `authorizations`, `signatures`, and `fees` encoded in the `calldataBytes` input must all be the same length.
    /// @dev For a set of burn intents, authorizations from other domains and those inadvertently submitted for
    ///      the same domain are ignored. The whole set is still needed to verify the signature.
    /// @dev See `lib/BurnIntents.sol` for encoding details
    ///
    /// @param calldataBytes     ABI-encoded (authorizations[], signatures[], fees[][]) arrays
    /// @param burnerSignature   Signature from `burnSigner` on `calldataBytes`
    function gatewayBurn(bytes calldata calldataBytes, bytes calldata burnerSignature) external whenNotPaused {
        // Verify that the calldata was signed by the expected signer
        _verifyBurnerSignature(calldataBytes, burnerSignature);

        // Decode the calldata into the authorizations, signatures, and fees arrays
        (bytes[] memory authorizations, bytes[] memory signatures, uint256[][] memory fees) =
            abi.decode(calldataBytes, (bytes[], bytes[], uint256[][]));

        // Process the burn intents
        _gatewayBurn(authorizations, signatures, fees);
    }

    /// Returns the byte encoding of a single burn intent
    ///
    /// @param authorization   The burn intent to encode
    /// @return                The byte-encoded burn intent
    function encodeBurnIntent(BurnIntent memory authorization) external pure returns (bytes memory) {
        return BurnIntentLib.encodeBurnIntent(authorization);
    }

    /// Returns the byte encoding of a set of burn intents
    ///
    /// @param authorizations   The burn intents to encode
    /// @return                 The byte-encoded burn intent set
    function encodeBurnIntents(BurnIntent[] memory authorizations) external pure returns (bytes memory) {
        BurnIntentSet memory authSet = BurnIntentSet({authorizations: authorizations});
        return BurnIntentLib.encodeBurnIntentSet(authSet);
    }

    /// Returns the `keccak256` hash of a burn intent
    ///
    /// @param authorization   The burn intent to hash
    /// @return                The `keccak256` hash of the burn intent
    function getTypedDataHash(bytes memory authorization) external view returns (bytes32) {
        return BurnIntentLib.getTypedDataHash(authorization);
    }

    /// Allows anyone to validate whether a set of burn intents would be valid if it were signed by the specified
    /// signer (which must match `sourceSigner` in the `TransferSpec`).
    ///
    /// @dev See `BurnIntents.sol` for encoding details
    ///
    /// @param authorization   A byte-encoded (set of) burn intent(s)
    /// @param signer          The address that will sign the burn intent(s)
    /// @return                `true` if the burn intent(s) would be valid with the given signer, `false`
    ///                        otherwise
    function validateBurnIntents(bytes memory authorization, address signer) external view returns (bool) {
        // Validate the burn intent(s) and get an iteration cursor
        Cursor memory cursor = BurnIntentLib.cursor(authorization);

        // Ensure there is at least one burn intent
        if (cursor.numAuths == 0) {
            revert MustHaveAtLeastOneBurnIntent();
        }

        // Iterate over the burn intents, validating each one
        bytes29 auth;
        address token;
        while (!cursor.done) {
            // Get the next burn intent
            auth = cursor.next();

            // Validate that everything about the burn intent is as expected, and skip if it's not for this domain
            bool relevant = _validateBurnIntent(auth, signer, 0, cursor.index - 1);
            if (!relevant) {
                continue;
            }

            // Ensure that each one we've seen so far is for the same token
            bytes29 spec = auth.getTransferSpec();
            address _token = AddressLib._bytes32ToAddress(spec.getSourceToken());
            if (token == address(0)) {
                token = _token;
            } else {
                if (_token != token) {
                    revert NotAllSameToken();
                }
            }
        }

        // If we get here, all burn intents are valid
        return true;
    }

    /// The address that may sign the calldata for burning tokens that have been minted on another domain
    ///
    /// @return   The stored burn signer
    function burnSigner() public view returns (address) {
        return BurnsStorage.get().burnSigner;
    }

    /// The address that will receive the onchain fee for burns
    ///
    /// @return   The stored fee recipient
    function feeRecipient() public view returns (address) {
        return BurnsStorage.get().feeRecipient;
    }

    /// Sets the address that may call `gatewayBurn`
    ///
    /// @dev May only be called by the `owner` role
    ///
    /// @param newBurnSigner   The new burn caller address
    function updateBurnSigner(address newBurnSigner) public onlyOwner {
        AddressLib._checkNotZeroAddress(newBurnSigner);

        BurnsStorage.Data storage $ = BurnsStorage.get();
        address oldBurnSigner = $.burnSigner;
        $.burnSigner = newBurnSigner;
        emit BurnSignerUpdated(oldBurnSigner, newBurnSigner);
    }

    /// Sets the address that will receive the fee for burns
    ///
    /// @dev May only be called by the `owner` role
    ///
    /// @param newFeeRecipient   The new fee recipient address
    function updateFeeRecipient(address newFeeRecipient) public onlyOwner {
        AddressLib._checkNotZeroAddress(newFeeRecipient);

        BurnsStorage.Data storage $ = BurnsStorage.get();
        address oldFeeRecipient = $.feeRecipient;
        $.feeRecipient = newFeeRecipient;
        emit FeeRecipientUpdated(oldFeeRecipient, newFeeRecipient);
    }

    /// Internal function to verify the signature of the `burnSigner` on the `calldataBytes` input
    ///
    /// @param calldataBytes     Calldata that includes all of authorizations, signatures, and fees
    /// @param burnerSignature   The signature from the `burnSigner` to verify
    function _verifyBurnerSignature(bytes calldata calldataBytes, bytes calldata burnerSignature) internal view {
        // Ensure that the signature is the expected length
        if (burnerSignature.length != 65) {
            revert InvalidBurnSigner();
        }

        // Verify the signature and revert if it's invalid
        address recoveredSigner = ECDSA.recover(keccak256(calldataBytes).toEthSignedMessageHash(), burnerSignature);
        if (recoveredSigner != BurnsStorage.get().burnSigner) {
            revert InvalidBurnSigner();
        }
    }

    /// Internal function that validates and processes burn intents.
    ///
    /// @param authorizations    A batch of byte-encoded burn intents or burn intent sets
    /// @param signatures        One signature for each burn intent (set)
    /// @param fees              The fees to be collected for each burn. Fees for burns on other domains are ignored and
    ///                          may be passed as zero. Each fee must be no more than `maxFee` of the corresponding burn
    ///                          authorization.
    function _gatewayBurn(bytes[] memory authorizations, bytes[] memory signatures, uint256[][] memory fees) internal {
        // Ensure there is at least one burn intent
        if (authorizations.length == 0) {
            revert MustHaveAtLeastOneBurnIntent();
        }

        // Ensure the top-level arrays are all of the same length. The nested arrays of fees will be checked later on.
        if (signatures.length != authorizations.length || fees.length != authorizations.length) {
            revert MismatchedBurn();
        }

        // Process each burn intent (set), validating and processing each one
        for (uint256 i = 0; i < authorizations.length; i++) {
            _validateAndProcessAuthorizationPayload(authorizations[i], signatures[i], fees[i]);
        }
    }

    /// Validates a single burn intent (set), recovers the signer, and processes all relevant burns
    ///
    /// @param authorization   The byte-encoded burn intent (set)
    /// @param signature       The signature on the `keccak256` hash of `authorization`
    /// @param fees            The fees to be charged, one for each individual burn intent
    function _validateAndProcessAuthorizationPayload(
        bytes memory authorization,
        bytes memory signature,
        uint256[] memory fees
    ) internal {
        // Validate the burn intent(s) and get an iteration cursor
        Cursor memory cursor = BurnIntentLib.cursor(authorization);

        // Ensure there is at least one burn intent
        if (cursor.numAuths == 0) {
            revert MustHaveAtLeastOneBurnIntent();
        }

        // Ensure there are the same number of fees as burn intents
        if (fees.length != cursor.numAuths) {
            revert MismatchedBurn();
        }

        // Recover the signer of the burn intent(s) and process each one
        bytes32 digest = _hashTypedData(BurnIntentLib.getTypedDataHash(authorization));
        address signer = ECDSA.recover(digest, signature);
        _processAuthorizationsAndBurn(cursor, signer, fees);
    }

    /// Iterates through a set of burn intents, validating and processing each relevant ones
    ///
    /// @param cursor   An initialized `Cursor` pointing to the start of the authorization set
    /// @param signer   The address that signed the entire burn intent payload
    /// @param fees     The fees to be charged, one for each individual burn intent
    function _processAuthorizationsAndBurn(Cursor memory cursor, address signer, uint256[] memory fees)
        internal
    {
        address token;
        bytes29 auth;
        uint32 index = 0;
        uint256 totalFee = 0;
        uint256 totalDeductedAmount = 0;

        while (!cursor.done) {
            index = cursor.index; // cursor.next() increments index, so get the current one first

            // Get the next burn intent and extract its transfer spec
            auth = cursor.next();
            bytes29 spec = auth.getTransferSpec();

            // Validate that everything about the burn intent is as expected, skipping if it's not for this domain
            bool relevant = _validateBurnIntent(auth, signer, fees[index], index);
            if (!relevant) {
                continue;
            }

            // Ensure that each one we've seen so far is for the same token
            address _token = AddressLib._bytes32ToAddress(spec.getSourceToken());
            if (token == address(0)) {
                token = _token;
            } else {
                if (_token != token) {
                    revert NotAllSameToken();
                }
            }

            // Reduce the balance of the depositor(s) and add to the total fee and burn amount
            (uint256 deductedAmount, uint256 actualFeeCharged) =
                _processSingleBurnIntent(spec, signer, fees[index]);
            totalDeductedAmount += deductedAmount;
            totalFee += actualFeeCharged;
        }

        // If there were no balance changes, it means none of the burn intents were relevant for this domain
        if (totalDeductedAmount == 0) {
            revert NoRelevantBurnIntents();
        }

        // Collect the fee
        IERC20(token).safeTransfer(feeRecipient(), totalFee);

        // Burn everything else
        IBurnToken(token).burn(totalDeductedAmount - totalFee);
    }

    /// Validates the contents of a single burn intent and its proposed fee
    ///
    /// @dev Checks include: non-zero value, source domain match, expiry block, fee limit, source contract address,
    ///      token support, and signer delegation
    ///
    /// @param auth        The `TypedMemView` reference to the encoded burn intent to validate
    /// @param signer      The address that signed the entire burn intent payload
    /// @param fee         The fee proposed for this burn intent
    /// @param index       The index of this burn intent within the original set (used for error messages)
    /// @return relevant   `true` if the burn intent is for the current domain, `false` otherwise
    function _validateBurnIntent(bytes29 auth, address signer, uint256 fee, uint32 index)
        internal
        view
        returns (bool relevant)
    {
        // Extract the `TransferSpec` from the burn intent
        bytes29 spec = auth.getTransferSpec();

        // If any burn intents are zero (even if they are for a different domain), refuse to continue so that
        // they all fail together across all source domains
        uint256 value = spec.getValue();
        if (value == 0) {
            revert AuthorizationValueMustBePositiveAtIndex(index);
        }

        // If the burn intent is for a different domain, perform no further checks and indicate that to the
        // caller so it can be skipped
        uint32 domain = spec.getSourceDomain();
        if (!_isCurrentDomain(domain)) {
            return false;
        }

        // Ensure that the burn intent is not expired
        uint256 maxBlockHeight = auth.getMaxBlockHeight();
        if (maxBlockHeight < block.number) {
            revert AuthorizationExpiredAtIndex(index, maxBlockHeight, block.number);
        }

        // Ensure that the fee is within the allowed range
        uint256 maxFee = auth.getMaxFee();
        if (maxFee < fee) {
            revert BurnFeeTooHighAtIndex(index, maxFee, fee);
        }

        // Ensure that this is the correct source contract
        address sourceContract = AddressLib._bytes32ToAddress(spec.getSourceContract());
        if (sourceContract != address(this)) {
            revert InvalidAuthorizationSourceContractAtIndex(index, sourceContract, address(this));
        }

        // Ensure that the source token is supported
        address sourceToken = AddressLib._bytes32ToAddress(spec.getSourceToken());
        if (!isTokenSupported(sourceToken)) {
            revert UnsupportedTokenAtIndex(index, sourceToken);
        }

        // Ensure that the signer of the burn intent matches what was provided in the `TransferSpec`
        address sourceSigner = AddressLib._bytes32ToAddress(spec.getSourceSigner());
        if (sourceSigner != signer) {
            revert InvalidAuthorizationSourceSignerAtIndex(index, sourceSigner, signer);
        }

        // Ensure that the signer of the burn intent was at one point authorized for the balance being burned.
        // Revoked authorizations are okay, to ensure that revocations cannot prevent burns
        address sourceDepositor = AddressLib._bytes32ToAddress(spec.getSourceDepositor());
        if (!_wasEverAuthorizedForBalance(sourceToken, sourceDepositor, signer)) {
            revert Delegation.NotAuthorized();
        }

        // If we get here, the burn intent is valid and relevant for this domain
        return true;
    }

    /// Processes a single valid burn intent: marks the transfer spec hash, reduces balance, and emits an event
    ///
    /// @dev Assumes the associated `TransferSpec` (`spec`) has already been validated for relevance to the current
    ///      domain and basic validity checks (e.g., non-zero value, expiry). It calculates the actual fee charged based
    ///      on available balance after deducting the value.
    /// @dev If the depositor has an insufficient balance to cover both the burn value and the fee, the burn value is
    ///      prioritized over the fee.
    ///
    /// @param spec                The `TypedMemView` reference to the `TransferSpec` from the burn intent
    /// @param signer              The address that signed the entire burn intent payload
    /// @param fee                 The fee to be charged for this burn intent
    /// @return deductedAmount     The total amount actually deducted from the depositor's balances (the value from the
    ///                            burn intent plus the actual fee charged). May be less than `value + fee` if
    ///                            the depositor had an insufficient balance to cover both.
    /// @return actualFeeCharged   The fee to be collected. May be less than `fee` if the depositor had an insufficient
    ///                            balance to cover both the full value and the fee.
    function _processSingleBurnIntent(bytes29 spec, address signer, uint256 fee)
        internal
        returns (uint256 deductedAmount, uint256 actualFeeCharged)
    {
        // Mark the transfer spec hash as used
        _checkAndMarkTransferSpecHash(spec.getHash());

        // Extract the relevant parameters from the `TransferSpec`
        address token = AddressLib._bytes32ToAddress(spec.getSourceToken());
        address depositor = AddressLib._bytes32ToAddress(spec.getSourceDepositor());
        uint256 value = spec.getValue();

        // Reduce the balances of the depositor by amount being burned + the fee, returning the total amounts that were
        // drawn from each balance type
        (uint256 fromAvailable, uint256 fromWithdrawing) = _reduceBalance(token, depositor, value + fee);

        // If the full amount could not be deducted, emit an event with the details. This should not happen under normal
        // circumstances and indicates a failure in the system, but we want to continue and burn what we can.
        deductedAmount = fromAvailable + fromWithdrawing;
        if (deductedAmount < value + fee) {
            emit InsufficientBalance(token, depositor, value + fee, fromAvailable, fromWithdrawing);
        }

        // If the full amount could not be deducted, we want to prioritize burning over taking the fee
        if (deductedAmount <= value) {
            actualFeeCharged = 0;
        } else {
            actualFeeCharged = deductedAmount - value;
        }

        // Emit an event with all the information about the burn
        emit GatewayBurned(
            token,
            depositor,
            spec.getHash(),
            spec.getDestinationDomain(),
            spec.getDestinationRecipient(),
            signer,
            deductedAmount - actualFeeCharged,
            actualFeeCharged,
            fromAvailable,
            fromWithdrawing
        );

        // Return the amount that was actually deducted and the actual fee charged
        return (deductedAmount, actualFeeCharged);
    }
}

/// @title BurnsStorage
///
/// @notice Implements the EIP-7201 storage pattern for the `Burns` module
library BurnsStorage {
    /// @custom:storage-location erc7201:circle.gateway.Burns
    struct Data {
        /// The address that may sign the calldata for burning tokens that have been minted on another chain
        address burnSigner;
        /// The address that will receive the onchain fee for burns
        address feeRecipient;
    }

    /// `keccak256(abi.encode(uint256(keccak256(bytes("circle.gateway.Burns"))) - 1)) & ~bytes32(uint256(0xff))`
    bytes32 public constant SLOT = 0x931ec06eaaa2cd8a002032d3364041b052af597aa8c169fcc20c959a9f557100;

    /// EIP-7201 getter for the storage slot
    ///
    /// @return $   The storage struct for the `Burns` module
    function get() internal pure returns (Data storage $) {
        assembly ("memory-safe") {
            $.slot := SLOT
        }
    }
}
