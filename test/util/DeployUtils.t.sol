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

import {Test} from "forge-std/Test.sol";
import {GatewayMinter} from "src/GatewayMinter.sol";
import {GatewayWallet} from "src/GatewayWallet.sol";
import {UpgradeablePlaceholder} from "src/UpgradeablePlaceholder.sol";
import {DeployUtils} from "test/util/DeployUtils.sol";

contract TestDeployUtils is Test, DeployUtils {
    address private owner = makeAddr("owner");
    uint32 private domain = 99;

    function test_deploy() external {
        (GatewayWallet wallet, GatewayMinter minter) = deploy(owner, domain);

        assertNotEq(address(wallet), address(0));
        assertNotEq(address(minter), address(0));
        assertEq(wallet.owner(), owner);
        assertEq(minter.owner(), owner);
        assert(!wallet.paused());
        assert(!minter.paused());
        assertEq(wallet.domain(), domain);
        assertEq(minter.domain(), domain);
    }

    function test_deployWalletOnly() external {
        GatewayWallet wallet = deployWalletOnly(owner, domain);

        assertNotEq(address(wallet), address(0));
        assertEq(wallet.owner(), owner);
        assert(!wallet.paused());
        assertEq(wallet.domain(), domain);
    }

    function test_deployMinterOnly() external {
        GatewayMinter minter = deployMinterOnly(owner, domain);

        assertNotEq(address(minter), address(0));
        assertEq(minter.owner(), owner);
        assert(!minter.paused());
        assertEq(minter.domain(), domain);
    }

    function test_deployPlaceholder() external {
        UpgradeablePlaceholder placeholder = deployPlaceholder(owner);

        assertNotEq(address(placeholder), address(0));
        assertEq(placeholder.owner(), owner);
    }

    function test_deployPlaceholderWithoutInitializing() external {
        UpgradeablePlaceholder placeholder = deployPlaceholderWithoutInitializing();

        assertNotEq(address(placeholder), address(0));
        assertEq(placeholder.owner(), address(0));
    }
}
