// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Script} from "forge-std/Script.sol";
import {AuthOnChain} from "../src/AuthOnChain.sol";

contract DeployAuthOnChain is Script {
    AuthOnChain authOnChain;

    function deployAuthOnChain() public returns (AuthOnChain) {
        uint256 privateKey = vm.envUint("PRIVATE_KEY");

        vm.startBroadcast(privateKey);
        authOnChain = new AuthOnChain();
        vm.stopBroadcast();

        return authOnChain;
    }

    function run() external returns (AuthOnChain) {
        return deployAuthOnChain();
    }
}
