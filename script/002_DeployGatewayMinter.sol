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

import {console} from "forge-std/console.sol";
import {EnvSelector, EnvConfig} from "script/000_Constants.sol";
import {BaseBytecodeDeployScript} from "script/BaseBytecodeDeployScript.sol";

/// @title DeployGatewayMinter
/// @notice Deployment script for GatewayMinter implementation and proxy with initialization
/// @dev Deploys in sequence:
///      1. UpgradeablePlaceholder implementation (temporary implementation)
///      2. GatewayMinter implementation (actual implementation)
///      3. ERC1967Proxy pointing to placeholder, then upgrades to actual implementation
contract DeployGatewayMinter is BaseBytecodeDeployScript {
    /// @dev Environment selector for multi-environment deployment
    EnvSelector private envSelector;

    constructor() {
        envSelector = new EnvSelector();
    }

    /// @dev Prepares initialization data for GatewayMinter
    /// @return Encoded initialization call data including all configuration parameters
    function prepareInitData() internal view returns (bytes memory) {
        address gatewayMinterPauser = vm.envAddress("GATEWAYMINTER_PAUSER_ADDRESS");
        address gatewayMinterDenylister = vm.envAddress("GATEWAYMINTER_DENYLISTER_ADDRESS");
        address[] memory supportedTokens = new address[](1);
        supportedTokens[0] = vm.envAddress("GATEWAYMINTER_SUPPORTED_TOKEN_1");
        uint32 domain = uint32(vm.envUint("GATEWAYMINTER_DOMAIN"));
        address attestationSigner = vm.envAddress("GATEWAYMINTER_ATTESTATION_SIGNER");

        address[] memory tokenAuthorities = new address[](1);
        tokenAuthorities[0] = vm.envOr("GATEWAYMINTER_TOKEN_AUTH_1", address(0));

        return abi.encodeWithSignature(
            "initialize(address,address,address[],uint32,address,address[])",
            gatewayMinterPauser,
            gatewayMinterDenylister,
            supportedTokens,
            domain,
            attestationSigner,
            tokenAuthorities
        );
    }

    /// @notice Main deployment function that sets up the entire GatewayMinter system
    /// @dev Deployment process:
    ///      1. Deploy placeholder implementation (minimal implementation for proxy initialization)
    ///      2. Deploy actual GatewayMinter implementation
    ///      3. Prepare proxy deployment data
    ///      4. Deploy and initialize proxy with prepared calls
    function run() public returns (address placeholderAddress, address implAddress, address proxyAddress) {
        address gatewayMinterOwner = vm.envAddress("GATEWAYMINTER_OWNER_ADDRESS");

        // Get environment configuration
        EnvConfig memory config = envSelector.getEnvironmentConfig();

        // Use environment-specific values or fallback to .env variables
        address deployer = config.deployerAddress;
        address factory = config.factoryAddress;
        bytes32 minterPlaceholderSalt = config.minterSalt;
        bytes32 minterImplSalt = config.minterSalt;
        bytes32 minterProxySalt = config.minterProxySalt;

        vm.startBroadcast(deployer);
        // Step 1: Deploy placeholder implementation
        placeholderAddress = deploy(factory, "UpgradeablePlaceholder.json", minterPlaceholderSalt, hex"");
        console.log("GatewayMinter placeholder address", placeholderAddress);

        // Step 2: Deploy actual GatewayMinter implementation
        implAddress = deploy(factory, "GatewayMinter.json", minterImplSalt, hex"");
        console.log("GatewayMinter implementation address", implAddress);

        // Step 3: Prepare proxy deployment data

        // Prepare UpgradeablePlaceholder constructor call data for initialization
        bytes memory constructorCallData =
            abi.encode(placeholderAddress, abi.encodeWithSignature("initialize(address)", factory));

        bytes[] memory proxyMultiCallData = new bytes[](2);
        // First call: Upgrade to actual implementation with initialization
        proxyMultiCallData[0] =
            abi.encodeWithSignature("upgradeToAndCall(address,bytes)", implAddress, prepareInitData());

        // Second call: Transfer ownership to final owner
        proxyMultiCallData[1] = abi.encodeWithSignature("transferOwnership(address)", gatewayMinterOwner);

        // Step 4: Deploy and initialize proxy
        proxyAddress =
            deployAndMultiCall(factory, "ERC1967Proxy.json", minterProxySalt, constructorCallData, proxyMultiCallData);
        console.log("GatewayMinter proxy address", proxyAddress);

        vm.stopBroadcast();
    }
}
