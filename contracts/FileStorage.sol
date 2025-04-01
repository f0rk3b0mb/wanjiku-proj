// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract AcademicCertificate {
    struct Certificate {
        string ipfsHash;
        address issuer;
        bool exists;
    }

    mapping(string => Certificate) private certificates;
    address public owner;

    event CertificateIssued(string indexed certificateId, string ipfsHash, address indexed issuer);

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Access denied: Only the owner can issue certificates");
        _;
    }

    function issueCertificate(string memory certificateId, string memory ipfsHash) public onlyOwner {
        require(!certificates[certificateId].exists, "Certificate ID already exists");
        
        certificates[certificateId] = Certificate(ipfsHash, msg.sender, true);

        emit CertificateIssued(certificateId, ipfsHash, msg.sender);
    }

    function verifyCertificate(string memory certificateId) public view returns (string memory) {
        require(certificates[certificateId].exists, "Certificate not found");
        return certificates[certificateId].ipfsHash;
    }

    function getIssuer(string memory certificateId) public view returns (address) {
        require(certificates[certificateId].exists, "Certificate not found");
        return certificates[certificateId].issuer;
    }
}
