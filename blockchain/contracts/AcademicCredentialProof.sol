// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

contract AcademicCredentialProof {
    address public owner;

    struct CredentialRecord {
        bytes32 credentialIdHash;
        bytes32 credentialHash;
        address issuer;
        uint256 issuedAt;
        bool revoked;
    }

    mapping(bytes32 => CredentialRecord) private credentials;
    mapping(bytes32 => bool) private credentialExists;

    event CredentialIssued(
        bytes32 indexed credentialIdHash,
        bytes32 indexed credentialHash,
        address indexed issuer,
        uint256 issuedAt
    );

    event CredentialRevoked(
        bytes32 indexed credentialIdHash,
        address indexed issuer,
        uint256 revokedAt
    );

    modifier onlyAuthorizedIssuer() {
        require(msg.sender == owner, "Only the authorized issuer can perform this action.");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function issueCredential(string calldata credentialId, bytes32 credentialHash)
        external
        onlyAuthorizedIssuer
    {
        bytes32 idHash = keccak256(bytes(credentialId));
        require(!credentialExists[idHash], "Credential already exists.");

        credentials[idHash] = CredentialRecord({
            credentialIdHash: idHash,
            credentialHash: credentialHash,
            issuer: msg.sender,
            issuedAt: block.timestamp,
            revoked: false
        });
        credentialExists[idHash] = true;

        emit CredentialIssued(idHash, credentialHash, msg.sender, block.timestamp);
    }

    function revokeCredential(string calldata credentialId) external onlyAuthorizedIssuer {
        bytes32 idHash = keccak256(bytes(credentialId));
        require(credentialExists[idHash], "Credential does not exist.");
        require(!credentials[idHash].revoked, "Credential has already been revoked.");

        credentials[idHash].revoked = true;

        emit CredentialRevoked(idHash, msg.sender, block.timestamp);
    }

    function getCredential(string calldata credentialId)
        external
        view
        returns (
            bytes32 credentialIdHash,
            bytes32 credentialHash,
            address issuer,
            uint256 issuedAt,
            bool revoked
        )
    {
        bytes32 idHash = keccak256(bytes(credentialId));
        require(credentialExists[idHash], "Credential does not exist.");

        CredentialRecord storage credential = credentials[idHash];
        return (
            credential.credentialIdHash,
            credential.credentialHash,
            credential.issuer,
            credential.issuedAt,
            credential.revoked
        );
    }

    function isCredentialValid(string calldata credentialId, bytes32 credentialHash)
        external
        view
        returns (bool)
    {
        bytes32 idHash = keccak256(bytes(credentialId));
        if (!credentialExists[idHash]) {
            return false;
        }

        CredentialRecord storage credential = credentials[idHash];
        return (!credential.revoked && credential.credentialHash == credentialHash);
    }
}
