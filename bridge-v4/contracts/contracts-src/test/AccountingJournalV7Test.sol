// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import {SP1AlphaRedemptionProofVerifierV3 as Verifier} from "../SP1AlphaRedemptionProofVerifierV3.sol";

// Executes the actual Solidity boundary against a Rust native-execution journal.
// SP1 cryptography and parent finality are deliberately exact-value mocks.
contract AccountingJournalV7Test {
    function run(bytes calldata journal) external returns (bool) {
        require(journal.length == 144, "journal size");
        AccountingSp1Mock sp1 = new AccountingSp1Mock(sha256(journal));
        AccountingParentMock parent = new AccountingParentMock(journal);
        Verifier verifier = new Verifier(Verifier.Parameters(address(sp1), address(sp1).codehash,
            sp1.VERIFIER_HASH(), bytes32(uint256(2)), bytes32(uint256(3)), bytes32(journal[:32]),
            address(parent), address(parent).codehash, parent.parentChainIdentity(),
            parent.finalityConfigHash(), 1123200));
        bytes memory proof = new bytes(500);
        for (uint i; i < 144; ++i) proof[i] = journal[i];
        bytes4 circuit = bytes4(sp1.VERIFIER_HASH());
        for (uint i; i < 4; ++i) proof[144+i] = circuit[i];
        bytes32 statement = bytes32(journal[32:64]);
        require(verifier.verify(statement, proof), "actual Rust journal rejected");
        require(!verifier.verify(bytes32(uint256(statement)^1), proof), "statement substitution");
        // Every journal field, plus the circuit prefix, is independently changed.
        uint[9] memory offsets = [uint(0),32,64,96,100,104,136,143,144];
        for (uint i; i < offsets.length; ++i) {
            proof[offsets[i]] ^= bytes1(uint8(1));
            require(!verifier.verify(statement, proof), "mutated envelope accepted");
            proof[offsets[i]] ^= bytes1(uint8(1));
        }
        // Reject tuple substitution even when both clocks agree and mock SP1 accepts.
        proof[103] ^= bytes1(uint8(1)); proof[143] ^= bytes1(uint8(1));
        sp1.setExpected(sha256(_journal(proof)));
        require(!verifier.verify(statement, proof), "wrong finalized tuple accepted");
        proof[103] ^= bytes1(uint8(1)); proof[143] ^= bytes1(uint8(1));
        sp1.setExpected(sha256(journal));
        parent.setAccepted(false);
        require(!verifier.verify(statement, proof), "unfinalized parent accepted");
        parent.setAccepted(true);
        sp1.setExpected(bytes32(0));
        require(!verifier.verify(statement, proof), "SP1 failure ignored");
        sp1.setExpected(sha256(journal));
        require(!verifier.verify(statement, bytes.concat(proof, hex"00")), "trailing bytes");
        assembly ("memory-safe") { mstore(proof, 499) }
        require(!verifier.verify(statement, proof), "truncated proof");
        return true;
    }
    function _journal(bytes memory proof) private pure returns (bytes memory out) {
        out = new bytes(144);
        for (uint i; i < 144; ++i) out[i] = proof[i];
    }
}
contract AccountingSp1Mock {
    bytes32 private expected;
    constructor(bytes32 value) { expected=value; }
    function VERIFIER_HASH() external pure returns(bytes32) { return sha256("accounting-test-circuit"); }
    function setExpected(bytes32 value) external { expected=value; }
    function verifyProof(bytes32 vkey, bytes calldata values, bytes calldata proof) external view {
        require(vkey==bytes32(uint256(3)) && sha256(values)==expected && proof.length==356);
    }
}
contract AccountingParentMock {
    bytes32 private immutable tuple;
    bool private accepted=true;
    constructor(bytes memory journal) {
        bytes32 hash; uint32 height; uint32 mtp; uint256 work;
        assembly ("memory-safe") {
            hash := mload(add(journal,96))
            height := shr(224,mload(add(journal,128)))
            mtp := shr(224,mload(add(journal,132)))
            work := mload(add(journal,136))
        }
        tuple=keccak256(abi.encode(hash,uint64(height),uint64(mtp),work));
    }
    function parentChainIdentity() external pure returns(bytes32) { return bytes32(uint256(4)); }
    function finalityConfigHash() external pure returns(bytes32) { return bytes32(uint256(5)); }
    function setAccepted(bool value) external { accepted=value; }
    function isFinalizedCanonical(bytes32 hash,uint64 height,uint64 mtp,uint256 work) external view returns(bool) {
        return accepted && tuple==keccak256(abi.encode(hash,height,mtp,work));
    }
}
