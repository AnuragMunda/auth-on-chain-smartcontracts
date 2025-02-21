// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test, console, console2} from "forge-std/Test.sol";
import {AuthOnChain} from "../../src/AuthOnChain.sol";

contract TestAuthOnChain is Test {
    AuthOnChain authOnChain;

    address deployer = makeAddr("deployer");
    address user = makeAddr("user");
    address guardian = makeAddr("guardian");
    address tom = makeAddr("tom");

    event AuthKeyRegistered(address indexed user);
    event AuthKeyVerified(address indexed user, bool success);
    event RecoveryGuardianSet(address indexed user, address indexed guardian);
    event AuthKeyRecovered(address indexed user);

    modifier registerUserAuthKey() {
        bytes32 hashedAuthKey = keccak256("0x12345");
        vm.prank(user);
        authOnChain.registerAuthKey(hashedAuthKey);
        _;
    }

    function setUp() external {
        vm.deal(deployer, 5 ether);
        vm.prank(deployer);
        authOnChain = new AuthOnChain();
    }

    function test_UserCanRegisterAuthKeyAndEmitsEvent() external {
        bytes32 hashedAuthKey = keccak256("AUTH_SECRET_KEY");

        vm.expectEmit(true, false, false, false);
        emit AuthKeyRegistered(user);

        vm.prank(user);
        authOnChain.registerAuthKey(hashedAuthKey);
    }

    function test_CannotRegisterIfAlreadyRegistered() external {
        bytes32 hashedAuthKey = keccak256("AUTH_SECRET_KEY");

        vm.prank(user);
        authOnChain.registerAuthKey(hashedAuthKey);

        vm.prank(user);
        vm.expectRevert(AuthOnChain.AuthOnChain_UserAlreadyRegistered.selector);
        authOnChain.registerAuthKey(hashedAuthKey);
    }

    function test_CannotPutInvalidHashedKey() external {
        vm.prank(user);
        vm.expectRevert(
            AuthOnChain.AuthOnChain_InvalidAuthenticationKey.selector
        );
        authOnChain.registerAuthKey(bytes32(0));
    }

    function test_VerifyAuthKeyAndEmitsEvent() external registerUserAuthKey {
        bytes32 signedAuthKey = keccak256("0x12345");
        vm.expectEmit(true, true, false, false);
        emit AuthKeyVerified(user, true);
        bool success = authOnChain.verifyAuthKey(user, signedAuthKey);

        assertTrue(success);
    }

    function test_ReturnsFalseIfAuthKeyDoesNotMatch()
        external
        registerUserAuthKey
    {
        bytes32 signedAuthKey = keccak256("0x12346");
        bool success = authOnChain.verifyAuthKey(user, signedAuthKey);

        assertFalse(success);
    }

    function test_CannotVerifyAuthKeyIfNotRegistered() external {
        bytes32 signedAuthKey = keccak256("0x12345");
        vm.expectRevert(AuthOnChain.AuthOnChain_UserNotRegistered.selector);
        authOnChain.verifyAuthKey(user, signedAuthKey);
    }

    function test_CannotVerifyIfInvalidAuthKeyGiven()
        external
        registerUserAuthKey
    {
        vm.expectRevert(
            AuthOnChain.AuthOnChain_InvalidAuthenticationKey.selector
        );
        authOnChain.verifyAuthKey(user, bytes32(0));
    }

    function test_UserCanSetGuardianAndEmitsEvent()
        external
        registerUserAuthKey
    {
        vm.expectEmit(true, true, false, false);
        emit RecoveryGuardianSet(user, guardian);
        vm.prank(user);
        authOnChain.setGuardian(guardian);
        address guardianAddr = authOnChain.getGuardian(user);

        assertEq(guardianAddr, guardian);
    }

    function test_CannotSetGuardianIfNotRegistered() external {
        vm.prank(user);
        vm.expectRevert(AuthOnChain.AuthOnChain_UserNotRegistered.selector);
        authOnChain.setGuardian(guardian);
    }

    function test_RevertIfGuardianAddressIsInvalid()
        external
        registerUserAuthKey
    {
        vm.prank(user);
        vm.expectRevert(AuthOnChain.AuthOnChain_InvalidAddress.selector);
        authOnChain.setGuardian(address(0));
    }

    function test_CannotSetSelfAsGuardian() external registerUserAuthKey {
        vm.prank(user);
        vm.expectRevert(AuthOnChain.AuthOnChain_GuardianCannotBeSelf.selector);
        authOnChain.setGuardian(user);
    }

    function test_RecoverAccountAndEmitsEvent() external registerUserAuthKey {
        bytes32 newHashedAuthKey = keccak256("0x12346");

        vm.prank(user);
        authOnChain.setGuardian(guardian);

        vm.expectEmit(true, false, false, false);
        emit AuthKeyRecovered(user);

        vm.prank(guardian);
        authOnChain.recoverAccount(user, newHashedAuthKey);
    }

    function test_CannotRecoverAccountIfInvalidAuthKey() external registerUserAuthKey {
        vm.prank(user);
        authOnChain.setGuardian(guardian);

        vm.prank(guardian);
        vm.expectRevert(AuthOnChain.AuthOnChain_InvalidAuthenticationKey.selector);
        authOnChain.recoverAccount(user, bytes32(0));
    }

    function test_CannotRecoverAccountIfCallerIsNotTheGuardian() external registerUserAuthKey {
        bytes32 newHashedAuthKey = keccak256("0x12346");

        vm.prank(user);
        authOnChain.setGuardian(guardian);

        vm.prank(tom);
        vm.expectRevert(AuthOnChain.AuthOnChain_NotAuthorizedGuardian.selector);
        authOnChain.recoverAccount(user, newHashedAuthKey);
    }
}
