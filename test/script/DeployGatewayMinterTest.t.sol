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
import {DeployGatewayMinter} from "../../script/002_DeployGatewayMinter.sol";
import {Create2Factory} from "../../script/Create2Factory.sol";

contract DeployGatewayMinterTest is Test {
    DeployGatewayMinter private deployer;

    function setUp() public {
        // Setup test environment variables
        vm.setEnv("ENV", "SMOKEBOX");

        // Create a factory for deterministic deployments
        address deployerAddress = makeAddr("deployer");
        Create2Factory factory = new Create2Factory(deployerAddress);

        // Set required environment variables
        vm.setEnv("CREATE2_FACTORY_ADDRESS", vm.toString(address(factory)));
        vm.setEnv("DEPLOYER_ADDRESS", vm.toString(deployerAddress));
        vm.setEnv("GATEWAYMINTER_OWNER_ADDRESS", vm.toString(makeAddr("minterOwner")));
        vm.setEnv("GATEWAYMINTER_PAUSER_ADDRESS", vm.toString(makeAddr("minterPauser")));
        vm.setEnv("GATEWAYMINTER_DENYLISTER_ADDRESS", vm.toString(makeAddr("minterDenylister")));
        vm.setEnv("GATEWAYMINTER_WALLET_ADDRESS", vm.toString(makeAddr("minterWallet")));
        vm.setEnv("GATEWAYMINTER_SUPPORTED_TOKEN_1", vm.toString(makeAddr("token1")));
        vm.setEnv("GATEWAYMINTER_DOMAIN", "1");
        vm.setEnv("GATEWAYMINTER_ATTESTATION_SIGNER", vm.toString(makeAddr("attestationSigner")));
        vm.setEnv("GATEWAYMINTER_TOKEN_AUTH_1", vm.toString(makeAddr("tokenAuth1")));

        // Initialize the deployer script
        deployer = new DeployGatewayMinter();
    }

    function testDeployGatewayMinter() public {
        // Execute the deployment script and verify the addresses.
        (address placeholderAddress, address implAddress, address proxyAddress) = deployer.run();
        assertEq(placeholderAddress, 0xB29a7d969bfC0064208FB57f601906EddBa699ed);
        assertEq(implAddress, 0x5E776Aae2F4830272da07427C292b481d88C9882);
        assertEq(proxyAddress, 0xd8c3011F8f5B6BfE359B43d3E04252cF73B9C475);
    }
}
