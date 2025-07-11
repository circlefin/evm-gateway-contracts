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

import {IERC1155Balance} from "src/interfaces/IERC1155Balance.sol";
import {WithdrawalDelay} from "src/modules/wallet/WithdrawalDelay.sol";

/// @title BalanceType
///
/// @notice The various balances that are tracked, used for the ERC-1155 balance functions
enum BalanceType {
    Total,
    Available,
    Withdrawing,
    Withdrawable
}

/// @title Balances
///
/// @notice Manages balances for the `GatewayWallet` contract
contract Balances is WithdrawalDelay, IERC1155Balance {
    /// Thrown when the ERC-1155 `balanceOfBatch` function is called with arrays of different lengths
    error InputArrayLengthMismatch();

    /// Thrown during attempted withdrawals when there is no withdrawing balance to withdraw
    error NoWithdrawingBalance();

    /// The total balance of a depositor for a token. This will always be equal to the sum of `availableBalance` and
    /// `withdrawingBalance`.
    ///
    /// @param token       The token of the requested balance
    /// @param depositor   The depositor of the requested balance
    /// @return            The total balance of the depositor for the token
    function totalBalance(address token, address depositor) public view returns (uint256) {
        BalancesStorage.Data storage $ = BalancesStorage.get();
        return $.availableBalances[token][depositor] + $.withdrawingBalances[token][depositor];
    }

    /// The balance that is available to the depositor, subject to deposits having been observed by the operator in a
    /// finalized block and no attestations having been issued but not yet burned by the operator
    ///
    /// @param token       The token of the requested balance
    /// @param depositor   The depositor of the requested balance
    /// @return            The available balance of the depositor for the token
    function availableBalance(address token, address depositor) public view returns (uint256) {
        return BalancesStorage.get().availableBalances[token][depositor];
    }

    /// The balance that is in the process of being withdrawn
    ///
    /// @param token       The token of the requested balance
    /// @param depositor   The depositor of the requested balance
    /// @return            The withdrawing balance of the depositor for the token
    function withdrawingBalance(address token, address depositor) public view returns (uint256) {
        return BalancesStorage.get().withdrawingBalances[token][depositor];
    }

    /// The balance that is withdrawable as of the current block. This will either be 0 or `withdrawingBalance`.
    ///
    /// @param token       The token of the requested balance
    /// @param depositor   The depositor of the requested balance
    /// @return            The withdrawable balance of the depositor for the token
    function withdrawableBalance(address token, address depositor) public view returns (uint256) {
        uint256 balanceToWithdraw = BalancesStorage.get().withdrawingBalances[token][depositor];
        if (balanceToWithdraw == 0 || withdrawalBlock(token, depositor) > block.number) {
            return 0;
        }

        return balanceToWithdraw;
    }

    /// The balance of a depositor for a particular token and balance type, compatible with ERC-1155
    ///
    /// @dev The "token" `id` is encoded as `uint256(bytes32(abi.encodePacked(uint96(BALANCE_TYPE), address(token))))`,
    ///      where `BALANCE_TYPE` is 0 for `Total`, 1 for `Available`, 2 for `Withdrawing`, and 3 for `Withdrawable`.
    ///
    /// @param depositor   The depositor of the requested balance
    /// @param id          The packed token and balance type
    /// @return balance    The balance of the depositor for the token and balance type
    function balanceOf(address depositor, uint256 id) public view override returns (uint256 balance) {
        address token = address(uint160(id));
        uint96 balanceTypeRaw = uint96(id >> 160);

        // Return 0 for invalid balance types
        if (balanceTypeRaw > uint96(type(BalanceType).max)) {
            return 0;
        }

        BalanceType balanceType = BalanceType(balanceTypeRaw);

        // Return the correct balance based on the balance type
        if (balanceType == BalanceType.Total) {
            balance = totalBalance(token, depositor);
        } else if (balanceType == BalanceType.Available) {
            balance = availableBalance(token, depositor);
        } else if (balanceType == BalanceType.Withdrawing) {
            balance = withdrawingBalance(token, depositor);
        } else if (balanceType == BalanceType.Withdrawable) {
            balance = withdrawableBalance(token, depositor);
        }
    }

    /// The batch version of `balanceOf`, compatible with ERC-1155
    ///
    /// @dev `depositors` and `ids` must be the same length
    /// @dev See the documentation for `balanceOf` for the format of `ids`
    ///
    /// @param depositors   The depositor of the requested balance
    /// @param ids          The packed token and balance type
    /// @return balances    The balances of the depositors for the tokens and balance types
    function balanceOfBatch(address[] calldata depositors, uint256[] calldata ids)
        external
        view
        override
        returns (uint256[] memory balances)
    {
        // Ensure the arrays are the same length
        if (depositors.length != ids.length) {
            revert InputArrayLengthMismatch();
        }

        // Fill in and return the results by calling `balanceOf`
        balances = new uint256[](depositors.length);
        for (uint256 i = 0; i < depositors.length; i++) {
            balances[i] = balanceOf(depositors[i], ids[i]);
        }
    }

    /// Increases a depositor's available balance by a specified value
    ///
    /// @param token       The token whose balance is being increased
    /// @param depositor   The depositor whose balance is being increased
    /// @param value       The amount to be added
    function _increaseAvailableBalance(address token, address depositor, uint256 value) internal {
        BalancesStorage.get().availableBalances[token][depositor] += value;
    }

    /// Moves a specified value from a depositor's available balance to their withdrawing balance
    ///
    /// @param token                 The token whose balance is being moved
    /// @param depositor             The depositor whose balance is being moved
    /// @param value                 The amount to be moved
    /// @return remainingAvailable   The remaining `available` balance after the move
    /// @return totalWithdrawing     The total `withdrawing` balance after the move
    function _moveBalanceToWithdrawing(address token, address depositor, uint256 value)
        internal
        returns (uint256 remainingAvailable, uint256 totalWithdrawing)
    {
        BalancesStorage.Data storage $ = BalancesStorage.get();

        remainingAvailable = $.availableBalances[token][depositor] - value;
        totalWithdrawing = $.withdrawingBalances[token][depositor] + value;

        $.availableBalances[token][depositor] = remainingAvailable;
        $.withdrawingBalances[token][depositor] = totalWithdrawing;
    }

    /// Decreases a depositor's withdrawing balance to zero, returning what it was beforehand
    ///
    /// @dev Reverts if the withdrawing balance is already zero
    ///
    /// @param token        The token whose balance is being withdrawn
    /// @param depositor    The depositor whose balance is being withdrawn
    /// @return withdrawn   The amount that was withdrawn
    function _emptyWithdrawingBalance(address token, address depositor) internal returns (uint256 withdrawn) {
        BalancesStorage.Data storage $ = BalancesStorage.get();

        uint256 balanceToWithdraw = $.withdrawingBalances[token][depositor];
        if (balanceToWithdraw == 0) {
            revert NoWithdrawingBalance();
        }

        $.withdrawingBalances[token][depositor] = 0;

        return balanceToWithdraw;
    }

    /// Reduces a depositor's balances by a specified value, prioritizing the available balance
    ///
    /// @param token              The token whose balance is being reduced
    /// @param depositor          The depositor whose balance is being reduced
    /// @param value              The amount to be reduced
    /// @return fromAvailable     The amount deducted from the `available` balance
    /// @return fromWithdrawing   The amount deducted from the `withdrawing` balance
    function _reduceBalance(address token, address depositor, uint256 value)
        internal
        returns (uint256 fromAvailable, uint256 fromWithdrawing)
    {
        BalancesStorage.Data storage $ = BalancesStorage.get();

        uint256 available = $.availableBalances[token][depositor];
        uint256 needed = value;

        // If there is enough in the available balance, deduct from it and return
        if (available >= needed) {
            $.availableBalances[token][depositor] -= needed;
            return (needed, 0);
        }

        // Otherwise, take it all and continue for the rest
        $.availableBalances[token][depositor] = 0;
        needed -= available;

        uint256 withdrawing = $.withdrawingBalances[token][depositor];

        // If there is enough in the withdrawing balance, deduct from it and return
        if (withdrawing >= needed) {
            $.withdrawingBalances[token][depositor] -= needed;
            return (available, needed);
        }

        // Otherwise, take it all
        $.withdrawingBalances[token][depositor] = 0;

        return (available, withdrawing);
    }
}

/// @title BalancesStorage
///
/// @notice Implements the EIP-7201 storage pattern for the `Balances` module
library BalancesStorage {
    /// @custom:storage-location erc7201:circle.gateway.Balances
    struct Data {
        /// The balances that have been deposited and are available for use (after finalization)
        mapping(address token => mapping(address depositor => uint256 value)) availableBalances;
        /// The balances that are in the process of being withdrawn and are no longer available
        mapping(address token => mapping(address depositor => uint256 value)) withdrawingBalances;
    }

    /// `keccak256(abi.encode(uint256(keccak256(bytes("circle.gateway.Balances"))) - 1)) & ~bytes32(uint256(0xff))`
    bytes32 public constant SLOT = 0xdd3dca88e892815d13ea80f1982e32e4fe3d0a89f03d14d3565bf56d58c31a00;

    /// EIP-7201 getter for the storage slot
    ///
    /// @return $   The storage struct for the `Balances` module
    function get() internal pure returns (Data storage $) {
        assembly ("memory-safe") {
            $.slot := SLOT
        }
    }
}
