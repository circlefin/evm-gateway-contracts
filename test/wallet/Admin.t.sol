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

import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {Test} from "forge-std/Test.sol";
import {GatewayWallet} from "src/GatewayWallet.sol";
import {WithdrawalDelay} from "src/modules/wallet/WithdrawalDelay.sol";
import {DeployUtils} from "test/util/DeployUtils.sol";
import {ForkTestUtils} from "test/util/ForkTestUtils.sol";

/// Tests admin functionality of GatewayWallet
contract GatewayWalletAdminTest is Test, DeployUtils {
    address private owner = makeAddr("owner");
    address private nonOwner = makeAddr("nonOwner");
    GatewayWallet private wallet;

    function setUp() public {
        wallet = deployWalletOnly(owner, ForkTestUtils.forkVars().domain);
    }

    function test_updateWithdrawalDelay_withdrawalDelayUpdatedByOwner() public {
        uint256 newDelay = 100;
        uint256 oldDelay = wallet.withdrawalDelay();
        vm.startPrank(owner);
        vm.expectEmit(true, true, false, false, address(wallet));
        emit WithdrawalDelay.WithdrawalDelayChanged(oldDelay, newDelay);
        wallet.updateWithdrawalDelay(newDelay);
        vm.stopPrank();
        assertEq(wallet.withdrawalDelay(), newDelay);

        // Update delay again
        oldDelay = newDelay;
        newDelay = 200;
        vm.startPrank(owner);
        vm.expectEmit(true, true, false, false, address(wallet));
        emit WithdrawalDelay.WithdrawalDelayChanged(oldDelay, newDelay);
        wallet.updateWithdrawalDelay(newDelay);
        vm.stopPrank();
        assertEq(wallet.withdrawalDelay(), newDelay);
    }

    function test_updateWithdrawalDelay_revertIfNotOwner() public {
        uint256 newDelay = 100;
        vm.startPrank(nonOwner);
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, nonOwner));
        wallet.updateWithdrawalDelay(newDelay);
        vm.stopPrank();
    }
}
