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
import {IBlacklistableToken} from "src/interfaces/IBlacklistableToken.sol";
import {IERC7597} from "src/interfaces/IERC7597.sol";
import {IERC7598} from "src/interfaces/IERC7598.sol";
import {AddressLib} from "src/lib/AddressLib.sol";
import {Denylist} from "src/modules/common/Denylist.sol";
import {Pausing} from "src/modules/common/Pausing.sol";
import {TokenSupport} from "src/modules/common/TokenSupport.sol";
import {Balances} from "src/modules/wallet/Balances.sol";

/// @title Deposits
///
/// @notice Manages deposits for the `GatewayWallet` contract
contract Deposits is Pausing, Denylist, TokenSupport, Balances {
    using SafeERC20 for IERC20;

    /// Emitted when a deposit is made
    ///
    /// @dev The `sender` will always be the same as `depositor`, except when a deposit is made using `depositFor`
    ///
    /// @param token       The token that was deposited
    /// @param depositor   The address that the resulting balance is credited to
    /// @param sender      The address that the funds were deposited from
    /// @param value       The amount that was deposited
    event Deposited(address indexed token, address indexed depositor, address indexed sender, uint256 value);

    /// Thrown for attempted zero-value deposits
    error DepositValueMustBePositive();
    /// @notice The token moved a different amount than requested (fee-on-transfer behaviour).
    error UnsupportedTokenTransferFee();

    /// Thrown when attempting to deposit for a blacklisted address
    ///
    /// @param depositor   The depositor who is blacklisted and cannot receive a deposit
    error DepositorIsBlacklisted(address depositor);

    /// Deposit tokens after approving this contract for the token
    ///
    /// @dev The resulting balance in this contract belongs to `msg.sender`
    ///
    /// @param token   The token to deposit
    /// @param value   The amount to be deposited
    function deposit(address token, uint256 value)
        external
        whenNotPaused
        notDenylisted(msg.sender)
        tokenSupported(token)
    {
        address depositor = msg.sender;
        address sender = msg.sender;
        _depositWithApproval(token, depositor, sender, value);
    }

    /// Deposit tokens on behalf of another address after approving this contract for the token
    ///
    /// @dev The resulting balance in this contract belongs to `depositor`, not `msg.sender`
    ///
    /// @param token       The token to deposit
    /// @param depositor   The address that should own the resulting balance
    /// @param value       The amount to be deposited
    function depositFor(address token, address depositor, uint256 value)
        external
        whenNotPaused
        notDenylisted(msg.sender)
        notDenylisted(depositor)
        tokenSupported(token)
    {
        // Ensure that the depositor is not the zero address
        AddressLib._checkNotZeroAddress(depositor);

        // Ensure that the depositor is not blacklisted
        if (IBlacklistableToken(token).isBlacklisted(depositor)) {
            revert DepositorIsBlacklisted(depositor);
        }

        address sender = msg.sender;
        _depositWithApproval(token, depositor, sender, value);
    }

    /// Deposit tokens with an EIP-2612 permit
    ///
    /// @dev The resulting balance in this contract belongs to the `owner` specified in the permit
    /// @dev The permit's `spender` must be the address of this contract
    /// @dev The full permitted `value` is always deposited
    ///
    /// @param token      The token to deposit
    /// @param owner      The depositor's address
    /// @param value      The amount to be deposited
    /// @param deadline   The unix time at which the signature expires, or max `uint256` value to signal no expiration
    /// @param v          v of the signature
    /// @param r          r of the signature
    /// @param s          s of the signature
    function depositWithPermit(
        address token,
        address owner,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external whenNotPaused notDenylisted(msg.sender) notDenylisted(owner) tokenSupported(token) {
        _depositWithPermit(token, owner, value, deadline, abi.encodePacked(r, s, v));
    }

    /// Deposit tokens with an EIP-7597 permit, passing the signature as bytes to allow for SCA deposits
    ///
    /// @dev The resulting balance in this contract belongs to the `owner` specified in the permit
    /// @dev The permit's `spender` must be the address of this contract
    /// @dev The full permitted `value` is always deposited
    /// @dev EOA wallet signatures should be packed in the order of r, s, v
    ///
    /// @param token       The token to deposit
    /// @param owner       The depositor's address
    /// @param value       The amount to be deposited
    /// @param deadline    The unix time at which the signature expires, or max `uint256` value to signal no expiration
    /// @param signature   Signature bytes signed by an EOA wallet or a contract wallet
    function depositWithPermit(address token, address owner, uint256 value, uint256 deadline, bytes calldata signature)
        external
        whenNotPaused
        notDenylisted(msg.sender)
        notDenylisted(owner)
        tokenSupported(token)
    {
        _depositWithPermit(token, owner, value, deadline, signature);
    }

    /// Deposit tokens with an ERC-3009 authorization
    ///
    /// @dev The resulting balance in this contract belongs to the `from` specified in the authorization
    /// @dev The authorization's `to` must be the address of this contract
    /// @dev The transfer will be done via `receiveWithAuthorization`
    ///
    /// @param token         The token to deposit
    /// @param from          The depositor's address
    /// @param value         The amount to be deposited
    /// @param validAfter    The time after which this is valid (unix time)
    /// @param validBefore   The time before which this is valid (unix time)
    /// @param nonce         Unique nonce
    /// @param v             v of the signature
    /// @param r             r of the signature
    /// @param s             s of the signature
    function depositWithAuthorization(
        address token,
        address from,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external whenNotPaused notDenylisted(msg.sender) notDenylisted(from) tokenSupported(token) {
        _depositWithAuthorization(token, from, value, validAfter, validBefore, nonce, abi.encodePacked(r, s, v));
    }

    /// Deposit tokens with an ERC-7598 authorization, passing the signature as bytes to allow for SCA deposits
    ///
    /// @dev The resulting balance in this contract belongs to the `from` specified in the authorization
    /// @dev The authorization's `to` must be the address of this contract
    /// @dev The transfer will be done via `receiveWithAuthorization`
    /// @dev EOA wallet signatures should be packed in the order of r, s, v
    ///
    /// @param token         The token to deposit
    /// @param from          The depositor's address
    /// @param value         The amount to be deposited
    /// @param validAfter    The time after which this is valid (unix time)
    /// @param validBefore   The time before which this is valid (unix time)
    /// @param nonce         Unique nonce
    /// @param signature     Signature bytes signed by an EOA wallet or a contract wallet
    function depositWithAuthorization(
        address token,
        address from,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        bytes calldata signature
    ) external whenNotPaused notDenylisted(msg.sender) notDenylisted(from) tokenSupported(token) {
        _depositWithAuthorization(token, from, value, validAfter, validBefore, nonce, signature);
    }

    /// Internal implementation for depositing tokens after approving this contract for the token
    ///
    /// @param token       The token to deposit
    /// @param depositor   The address that should own the resulting balance
    /// @param sender      The address that the funds should be deposited from
    /// @param value       The amount to be deposited
    function _depositWithApproval(address token, address depositor, address sender, uint256 value) internal {
        if (value == 0) {
            revert DepositValueMustBePositive();
        }

        // Checks-Effects-Interactions: transfer first, then credit the amount actually received.
        // This path previously credited `value` BEFORE the `safeTransferFrom`, and never verified
        // how much arrived. For a token that charges a transfer fee, the depositor was credited
        // the nominal amount while the contract received less, socialising the shortfall onto
        // other depositors at `withdraw`. Crediting after transfer also guarantees that a callback-
        // capable token cannot reenter and observe an already-inflated balance.
        uint256 balanceBefore = IERC20(token).balanceOf(address(this));
        IERC20(token).safeTransferFrom(sender, address(this), value);
        uint256 received = IERC20(token).balanceOf(address(this)) - balanceBefore;

        if (received != value) {
            revert UnsupportedTokenTransferFee();
        }

        // Increase the depositor's available balance
        _increaseAvailableBalance(token, depositor, received);

        // Emit an event to signal the deposit
        emit Deposited(token, depositor, sender, received);
    }

    /// Internal implementation for depositing tokens using an EIP-2612 permit
    ///
    /// @param token       The address of a token that supports EIP-2612 permits
    /// @param owner       The address that owns the tokens and signed the permit
    /// @param value       The amount to deposit
    /// @param deadline    The unix timestamp after which the permit signature expires
    /// @param signature   The signature bytes containing v, r, s components
    function _depositWithPermit(address token, address owner, uint256 value, uint256 deadline, bytes memory signature)
        internal
    {
        if (value == 0) {
            revert DepositValueMustBePositive();
        }

        address depositor = owner;

        // Execute the permit to approve this contract
        IERC7597(token).permit(depositor, address(this), value, deadline, signature);

        // Checks-Effects-Interactions: transfer first, verify received amount matches, then credit.
        uint256 balanceBefore = IERC20(token).balanceOf(address(this));
        IERC20(token).safeTransferFrom(depositor, address(this), value);
        uint256 received = IERC20(token).balanceOf(address(this)) - balanceBefore;

        if (received != value) {
            revert UnsupportedTokenTransferFee();
        }

        // Increase the depositor's available balance
        _increaseAvailableBalance(token, depositor, received);

        // Emit an event to signal the deposit
        emit Deposited(token, owner, owner, received);
    }

    /// @dev Internal implementation for depositing tokens using an ERC-7598 authorization
    ///
    /// @param token         The token to deposit
    /// @param from          The depositor's address
    /// @param value         The amount to be deposited
    /// @param validAfter    The time after which this is valid (unix time)
    /// @param validBefore   The time before which this is valid (unix time)
    /// @param nonce         Unique nonce
    /// @param signature     Signature bytes signed by an EOA wallet or a contract wallet
    function _depositWithAuthorization(
        address token,
        address from,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        bytes memory signature
    ) internal {
        if (value == 0) {
            revert DepositValueMustBePositive();
        }

        address depositor = from;

        // Sample balance BEFORE the authorization transfer executes to measure the real delta accurately.
        uint256 balanceBefore = IERC20(token).balanceOf(address(this));

        // Execute the authorization to transfer the tokens from the depositor to this contract.
        IERC7598(token).receiveWithAuthorization(
            depositor, address(this), value, validAfter, validBefore, nonce, signature
        );

        uint256 received = IERC20(token).balanceOf(address(this)) - balanceBefore;

        if (received != value) {
            revert UnsupportedTokenTransferFee();
        }

        // Increase the depositor's available balance
        _increaseAvailableBalance(token, depositor, received);

        // Emit an event to signal the deposit
        emit Deposited(token, depositor, depositor, received);
    }
}