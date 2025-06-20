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

import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";

/// @title WithdrawalDelay
///
/// @notice Manages the delay between initiating and completing withdrawals for the `GatewayWallet` contract.
contract WithdrawalDelay is Ownable2StepUpgradeable {
    /// Emitted when the withdrawal delay is updated
    ///
    /// @param oldDelay   The old value of the delay, in blocks
    /// @param newDelay   The new value of the delay, in blocks
    event WithdrawalDelayChanged(uint256 indexed oldDelay, uint256 indexed newDelay);

    /// Thrown when the required withdrawal delay has not yet passed since the most recent withdrawal was initiated
    error WithdrawalNotYetAvailable();

    /// Initializes the `withdrawalDelay`
    ///
    /// @param withdrawalDelay_   The initial value for the delay, in blocks
    function __WithdrawalDelay_init(uint256 withdrawalDelay_) internal onlyInitializing {
        updateWithdrawalDelay(withdrawalDelay_);
    }

    /// The number of blocks that must pass after calling `initiateWithdrawal` before a withdrawal can be completed
    ///
    /// @return   The number of blocks that must pass
    function withdrawalDelay() public view returns (uint256) {
        return WithdrawalDelayStorage.get().withdrawalDelay;
    }

    /// The block height at which an in-progress withdrawal is withdrawable
    ///
    /// @dev Returns 0 if there is no in-progress withdrawal
    ///
    /// @param token       The token of the requested balance
    /// @param depositor   The depositor of the requested balance
    /// @return            The block number at which the withdrawal will be withdrawable
    function withdrawalBlock(address token, address depositor) public view returns (uint256) {
        return WithdrawalDelayStorage.get().withdrawableAtBlocks[token][depositor];
    }

    /// Sets the number of blocks that must pass before a withdrawal can be completed. Care must be taken for the
    /// difference between `block.number` and RPC block number for certain networks.
    ///
    /// @dev May only be called by the `owner` role
    ///
    /// @param newDelay   The new value of the delay, in blocks
    function updateWithdrawalDelay(uint256 newDelay) public onlyOwner {
        uint256 oldDelay = WithdrawalDelayStorage.get().withdrawalDelay;
        WithdrawalDelayStorage.get().withdrawalDelay = newDelay;
        emit WithdrawalDelayChanged(oldDelay, newDelay);
    }

    /// Reverts if the given depositor may not yet withdraw the given token
    ///
    /// @param token       The token to check
    /// @param depositor   The depositor to check
    function _ensureWithdrawable(address token, address depositor) internal view {
        if (WithdrawalDelayStorage.get().withdrawableAtBlocks[token][depositor] > block.number) {
            revert WithdrawalNotYetAvailable();
        }
    }

    /// Sets the block height at which an in-progress withdrawal will be withdrawable
    ///
    /// @param token         The token that will be withdrawn
    /// @param depositor     The depositor of the funds being withdrawn
    /// @param blockNumber   The block number at which the withdrawal will be withdrawable
    function _setWithdrawalBlock(address token, address depositor, uint256 blockNumber) internal {
        WithdrawalDelayStorage.get().withdrawableAtBlocks[token][depositor] = blockNumber;
    }
}

/// @title WithdrawalDelayStorage
///
/// @notice Implements the EIP-7201 storage pattern for the `WithdrawalDelay` module
library WithdrawalDelayStorage {
    /// @custom:storage-location erc7201:circle.gateway.WithdrawalDelay
    struct Data {
        /// The block numbers at which in-progress withdrawals will be withdrawable
        mapping(address token => mapping(address depositor => uint256 block)) withdrawableAtBlocks;
        /// The number of blocks a user must wait after initiating a withdrawal before that amount is withdrawable. This
        /// value is added to the current block number when a withdrawal is initiated.
        uint256 withdrawalDelay;
    }

    /// `keccak256(abi.encode(uint256(keccak256(bytes("circle.gateway.WithdrawalDelay"))) - 1)) & ~bytes32(uint256(0xff))`
    bytes32 public constant SLOT = 0x8f0d2169d60e1d6e8f336adc673aa9b36c7a3956bc915f85e5cfebff815daa00;

    /// EIP-7201 getter for the storage slot
    ///
    /// @return $   The storage struct for the `WithdrawalDelay` module
    function get() internal pure returns (Data storage $) {
        assembly ("memory-safe") {
            $.slot := SLOT
        }
    }
}
