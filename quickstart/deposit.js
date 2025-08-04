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

import { account, ethereum, base, avalanche } from "./setup.js";

const DEPOSIT_AMOUNT = 10_000000n; // 10 USDC

// Deposit into the GatewayWallet contract on all chains
for (const chain of [ethereum, base, avalanche]) {
  // Get the wallet's current USDC balance
  console.log(`Checking USDC balance on ${chain.name}...`);
  const balance = await chain.usdc.read.balanceOf([account.address]);

  // Ensure the balance is sufficient for the deposit
  if (balance < DEPOSIT_AMOUNT) {
    console.error(`Insufficient USDC balance on ${chain.name}!`);
    console.error("Please top up at https://faucet.circle.com.");
    process.exit(1);
  }

  // Attempt to approve and deposit USDC into the GatewayWallet contract, and
  // handle the error if the waallet does not have enough funds to pay for gas
  try {
    // Approve the GatewayWallet contract for the wallet's USDC
    console.log("Approving the GatewayWallet contract for USDC...");
    const approvalTx = await chain.usdc.write.approve([chain.gatewayWallet.address, DEPOSIT_AMOUNT]);
    await chain.client.waitForTransactionReceipt({ hash: approvalTx });
    console.log("Done! Transaction hash:", approvalTx);

    // Deposit USDC into the GatewayWallet contract
    console.log("Depositing USDC into the GatewayWallet contract...");
    const depositTx = await chain.gatewayWallet.write.deposit([chain.usdc.address, DEPOSIT_AMOUNT]);
    await chain.client.waitForTransactionReceipt({ hash: depositTx });
    console.log("Done! Transaction hash:", depositTx);
  } catch (error) {
    if (error.details?.includes("insufficient funds")) {
      // If there wasn't enough for gas, log an error message and exit
      console.error(`The wallet does not have enough ${chain.currency} to pay for gas on ${chain.name}!`);
      console.error(`Please top up using a faucet.`);
    } else {
      // Log any other errors for debugging
      console.error(error);
    }
    process.exit(1);
  }
}
