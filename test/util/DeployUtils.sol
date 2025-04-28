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

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {CommonBase} from "forge-std/Base.sol";
import {GatewayMinter} from "src/GatewayMinter.sol";
import {GatewayWallet} from "src/GatewayWallet.sol";
import {UpgradeablePlaceholder} from "src/UpgradeablePlaceholder.sol";

/// Helpers for deploying the contracts during tests
abstract contract DeployUtils is CommonBase {
    function deploy(address owner, uint32 domain) public returns (GatewayWallet, GatewayMinter) {
        // Deploy both placeholders
        UpgradeablePlaceholder walletProxy = deployPlaceholder(owner);
        UpgradeablePlaceholder minterProxy = deployPlaceholder(owner);

        // Deploy both implementation contracts
        GatewayWallet walletImpl = new GatewayWallet();
        GatewayMinter minterImpl = new GatewayMinter();

        // Upgrade both placeholders and tell them about each other
        vm.prank(owner);
        walletProxy.upgradeToAndCall(
            address(walletImpl), _walletInitializationCall(owner, address(minterProxy), domain)
        );
        vm.prank(owner);
        minterProxy.upgradeToAndCall(
            address(minterImpl), _minterInitializationCall(owner, address(walletProxy), domain)
        );
        vm.stopPrank();

        // Return the upgraded proxies
        GatewayWallet wallet = GatewayWallet(address(walletProxy));
        GatewayMinter minter = GatewayMinter(address(minterProxy));
        return (wallet, minter);
    }

    function deployWalletOnly(address owner, uint32 domain) public returns (GatewayWallet) {
        UpgradeablePlaceholder walletProxy = deployPlaceholder(owner);
        GatewayWallet walletImpl = new GatewayWallet();
        vm.prank(owner);
        walletProxy.upgradeToAndCall(address(walletImpl), _walletInitializationCall(owner, address(0), domain));
        return GatewayWallet(address(walletProxy));
    }

    function deployMinterOnly(address owner, uint32 domain) public returns (GatewayMinter) {
        UpgradeablePlaceholder minterProxy = deployPlaceholder(owner);
        GatewayMinter minterImpl = new GatewayMinter();
        vm.prank(owner);
        minterProxy.upgradeToAndCall(address(minterImpl), _minterInitializationCall(owner, address(0), domain));
        return GatewayMinter(address(minterProxy));
    }

    function deployPlaceholder(address owner) public returns (UpgradeablePlaceholder) {
        return _deployPlaceholder(abi.encodeCall(UpgradeablePlaceholder.initialize, owner));
    }

    function deployPlaceholderWithoutInitializing() public returns (UpgradeablePlaceholder) {
        return _deployPlaceholder(new bytes(0));
    }

    function _deployPlaceholder(bytes memory initData) private returns (UpgradeablePlaceholder) {
        UpgradeablePlaceholder placeholder = new UpgradeablePlaceholder();
        ERC1967Proxy proxy = new ERC1967Proxy(address(placeholder), initData);
        return UpgradeablePlaceholder(address(proxy));
    }

    function _walletInitializationCall(address owner, address minter, uint32 domain)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodeCall(
            GatewayWallet.initialize,
            (
                owner, // pauser
                owner, // denylister
                minter, // minter contract
                _initiallySupportedTokens(), // supported tokens
                domain, // domain
                0, // withdrawal delay
                owner, // burn signer
                owner // fee recipient
            )
        );
    }

    function _minterInitializationCall(address owner, address wallet, uint32 domain)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodeCall(
            GatewayMinter.initialize,
            (
                owner, // pauser
                owner, // denylister
                wallet, // wallet contract
                _initiallySupportedTokens(), // supported tokens
                domain, // domain
                owner, // mint authorization signer
                _initialTokenMintAuthorities() // token mint authorities
            )
        );
    }

    function _initiallySupportedTokens() internal pure returns (address[] memory) {
        address[] memory tokens = new address[](3);
        tokens[0] = address(0xaaaa);
        tokens[1] = address(0xbbbb);
        tokens[2] = address(0xcccc);
        return tokens;
    }

    function _initialTokenMintAuthorities() internal pure returns (address[] memory) {
        address[] memory authorities = new address[](3);
        authorities[0] = address(0x1111);
        authorities[1] = address(0);
        authorities[2] = address(0x3333);
        return authorities;
    }
}
