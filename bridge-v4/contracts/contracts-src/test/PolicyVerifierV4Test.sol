// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import {SP1PolicyAcceptanceVerifierV4 as Verifier} from "../SP1PolicyAcceptanceVerifierV4.sol";
contract PolicySP1Mock {
    function VERIFIER_HASH() external pure returns(bytes32) { return bytes32(uint256(1)<<248); }
    function verifyProof(bytes32 key,bytes calldata journal,bytes calldata proof) external pure {
        require(key==bytes32(uint256(7)) && journal.length==64 && proof.length==356);
        require(uint8(proof[355])==0);
    }
}
contract PolicyVerifierV4Test {
    function run() external returns(bool) {
        PolicySP1Mock mock=new PolicySP1Mock();
        Verifier v=new Verifier(address(mock),address(mock).codehash,mock.VERIFIER_HASH(),bytes32(uint256(6)),bytes32(uint256(7)));
        bytes32 statement=bytes32(uint256(8)); bytes32 policy=bytes32(uint256(9));
        bytes memory groth=new bytes(356); groth[0]=0x01;
        bytes memory envelope=abi.encodePacked(statement,policy,groth);
        require(v.verifyProof(statement,policy,envelope),"valid envelope");
        require(!v.verifyProof(statement,bytes32(uint256(10)),envelope),"policy substitution");
        require(!v.verifyProof(bytes32(uint256(10)),policy,envelope),"statement substitution");
        require(!v.verifyProof(statement,policy,abi.encodePacked(statement,groth)),"legacy journal");
        require(!v.verifyProof(statement,policy,bytes.concat(envelope,hex"00")),"trailing byte");
        envelope[64]=0x02;
        require(!v.verifyProof(statement,policy,envelope),"wrong circuit");
        envelope[64]=0x01; envelope[419]=0x01;
        require(!v.verifyProof(statement,policy,envelope),"SP1 rejection");
        return true;
    }
}
