// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

contract AuthOnChain {
    /*==============================================================
                                ERRORS
    ==============================================================*/
    error AuthOnChain_InvalidAddress();
    error AuthOnChain_UserNotRegistered();
    error AuthOnChain_UserAlreadyRegistered();
    error AuthOnChain_InvalidAuthenticationKey();
    error AuthOnChain_GuardianCannotBeSelf();
    error AuthOnChain_NotAuthorizedGuardian();

    /*==============================================================
                            STATE VARIABLES
    ==============================================================*/
    mapping(address user => bytes32 hashedKeys) private s_authKeys;
    mapping(address user => address guardian) private s_recoveryGuardians;

    /*==============================================================
                                EVENTS
    ==============================================================*/
    event AuthKeyRegistered(address indexed user);
    event RecoveryGuardianSet(address indexed user, address indexed guardian);
    event AuthKeyRecovered(address indexed user);

    /*==============================================================
                            FUNCTION MODIFIERS
    ==============================================================*/
    modifier shouldBeRegistered(address _user) {
        require(
            s_authKeys[_user] != bytes32(0),
            AuthOnChain_UserNotRegistered()
        );
        _;
    }

    modifier validateAuthenticationKey(bytes32 _authKey) {
        require(_authKey != bytes32(0), AuthOnChain_InvalidAuthenticationKey());
        _;
    }

    /*==============================================================
                                FUNCTIONS
    ==============================================================*/
    function registerAuthKey(
        bytes32 _hashedAuthKey
    )
        external
        validateAuthenticationKey(_hashedAuthKey)
    {
        require(
            s_authKeys[msg.sender] == bytes32(0),
            AuthOnChain_UserAlreadyRegistered()
        );
        s_authKeys[msg.sender] = _hashedAuthKey;
        emit AuthKeyRegistered(msg.sender);
    }

    function verifyAuthKey(
        address _user,
        bytes32 _hashedSignedKey
    )
        external
        view
        shouldBeRegistered(_user)
        validateAuthenticationKey(_hashedSignedKey)
        returns (bool)
    {
        bool isVerified = s_authKeys[_user] == _hashedSignedKey;
        return isVerified;
    }

    function setGuardian(
        address _guardian
    ) external shouldBeRegistered(msg.sender) {
        require(_guardian != address(0), AuthOnChain_InvalidAddress());
        require(_guardian != msg.sender, AuthOnChain_GuardianCannotBeSelf());

        s_recoveryGuardians[msg.sender] = _guardian;
        emit RecoveryGuardianSet(msg.sender, _guardian);
    }

    function recoverAccount(
        address _user,
        bytes32 _newHashedAuthKey
    ) external validateAuthenticationKey(_newHashedAuthKey) {
        require(
            s_recoveryGuardians[_user] == msg.sender,
            AuthOnChain_NotAuthorizedGuardian()
        );

        s_authKeys[_user] = _newHashedAuthKey;
        emit AuthKeyRecovered(_user);
    }

    function getGuardian(address _user) external view returns (address) {
        return s_recoveryGuardians[_user];
    }

    function isRegistered(address _user) external view returns (bool) {
        return s_authKeys[_user] != bytes32(0) ;
    }
}
