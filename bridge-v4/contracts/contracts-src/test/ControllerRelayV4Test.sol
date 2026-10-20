// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import {ControllerAcceptanceRelayV4 as Relay} from "../ControllerAcceptanceRelayV4.sol";
import {IControllerAcceptanceRelayV4 as API} from "../interfaces/IControllerAcceptanceRelayV4.sol";
import {ControllerAcceptanceStateCodecV4 as Codec} from "../ControllerAcceptanceStateCodecV4.sol";

// Test doubles only: no cryptographic or chain-authentication evidence.
contract RelayBoundaryV4Mock {
    bool public proofAccepted;
    bytes32 public expectedStatement;
    bytes32 public deniedBlock;
    bytes32 public expectedPolicy = bytes32(uint256(99));
    function verifierProgramId() external pure returns(bytes32) { return bytes32(uint256(1)); }
    function verifierConfigHash() external pure returns(bytes32) { return bytes32(uint256(2)); }
    function parentChainIdentity() external pure returns(bytes32) { return bytes32(uint256(1)); }
    function finalityConfigHash() external pure returns(bytes32) { return bytes32(uint256(2)); }
    function securityModelId() external pure returns(bytes32) { return bytes32(uint256(3)); }
    function currentFinalizedHeight() external pure returns(uint64) { return 100; }
    function isFinalizedCanonical(bytes32 hash,uint64,uint64,uint256) external view returns(bool) {
        return hash != deniedBlock;
    }
    function isAcceptedAnchor(bytes32,bytes32,uint64) external pure returns(bool) { return true; }
    function verifyProof(bytes32 statement,bytes32 policy,bytes calldata) external view returns(bool) {
        return proofAccepted && statement == expectedStatement && policy == expectedPolicy;
    }
    function setPolicy(bytes32 policy) external { expectedPolicy=policy; }
    function setProof(bytes32 statement,bool accepted) external { expectedStatement=statement; proofAccepted=accepted; }
    function deny(bytes32 hash) external { deniedBlock=hash; }
}

contract ControllerRelayV4Test {
    function statementVector() external returns(bytes32[4] memory result) {
        RelayBoundaryV4Mock mock=new RelayBoundaryV4Mock();
        Relay.Transition memory t;
        t.source=API.AcceptanceState(bytes32(uint256(10)),bytes32(uint256(11)),bytes32(uint256(12)),
            0,0,0,bytes32(uint256(13)),1,1,bytes32(uint256(1)),1,1);
        t.successor=API.AcceptanceState(bytes32(uint256(20)),bytes32(uint256(21)),bytes32(uint256(12)),
            1,0,0,bytes32(uint256(23)),2,2,bytes32(uint256(2)),2,2);
        t.executionCommitment=bytes32(uint256(30)); t.elementsBlockHash=bytes32(uint256(31));
        t.elementsBlockHeight=0x0102030405060708; t.transactionId=bytes32(uint256(32));
        t.canonicalTipContextCommitment=bytes32(uint256(33)); t.canonicalTipBlockHash=bytes32(uint256(34));
        t.canonicalTipHeight=0x1112131415161718; t.canonicalTipMedianTimePast=0x2122232425262728;
        t.canonicalTipChainwork=uint256(1)<<200;
        t.acceptedAnchorStateCommitment=bytes32(uint256(35));
        t.acceptedAnchorExecutionCheckpointHash=bytes32(uint256(36)); t.acceptedAnchorSequence=0x3132333435363738;
        Relay.Boundary memory b=Relay.Boundary(address(mock),address(mock).codehash,bytes32(uint256(1)),bytes32(uint256(2)));
        Relay relay=new Relay(Relay.Config(b,b,b,bytes32(uint256(3)),bytes32(uint256(4)),
            bytes32(uint256(5)),sha256(Codec.encode(t.source)),60,bytes32(uint256(99))));
        return [bytes32(block.chainid),bytes32(uint256(uint160(address(relay)))),relay.verifierConfigHash(),relay.transitionPublicValuesHash(t)];
    }
    function codecVector() external pure returns(bytes memory) {
        return Codec.encode(API.AcceptanceState(
            hex"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            hex"202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
            hex"404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
            0x0102030405060708,0x1112131415161718,0x2122232425262728,
            hex"606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f",
            0x3132333435363738,0x4142434445464748,
            hex"808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
            0x5152535455565758,0x6162636465666768));
    }
    function run() external returns(bool) {
        RelayBoundaryV4Mock mock = new RelayBoundaryV4Mock();
        Relay.Transition memory t;
        t.source = API.AcceptanceState(bytes32(uint256(10)),bytes32(uint256(11)),bytes32(uint256(12)),
            0,0,0,bytes32(uint256(13)),1,1,bytes32(uint256(1)),1,1);
        require(Codec.encode(t.source).length == 226,"codec length");
        t.successor = API.AcceptanceState(bytes32(uint256(20)),bytes32(uint256(21)),bytes32(uint256(12)),
            1,0,0,bytes32(uint256(23)),2,2,bytes32(uint256(2)),2,2);
        t.executionCommitment=bytes32(uint256(30)); t.elementsBlockHash=bytes32(uint256(31));
        t.elementsBlockHeight=1; t.transactionId=bytes32(uint256(32));
        t.canonicalTipContextCommitment=bytes32(uint256(33)); t.canonicalTipBlockHash=bytes32(uint256(34));
        t.canonicalTipHeight=8; t.canonicalTipMedianTimePast=8; t.canonicalTipChainwork=8;
        t.acceptedAnchorStateCommitment=bytes32(uint256(35));
        t.acceptedAnchorExecutionCheckpointHash=bytes32(uint256(36)); t.acceptedAnchorSequence=1;
        Relay.Boundary memory boundary=Relay.Boundary(address(mock),address(mock).codehash,bytes32(uint256(1)),bytes32(uint256(2)));
        Relay relay=new Relay(Relay.Config(boundary,boundary,boundary,bytes32(uint256(3)),
            bytes32(uint256(4)),bytes32(uint256(5)),sha256(Codec.encode(t.source)),60,bytes32(uint256(99))));
        bytes32 statement=relay.transitionPublicValuesHash(t);
        require(!_advance(relay,t),"bad proof accepted");
        require(!relay.initialized(),"failed proof changed state");
        mock.setProof(statement,true);
        mock.setPolicy(bytes32(uint256(100)));
        require(!_advance(relay,t),"substituted policy accepted");
        require(!relay.initialized(),"policy rejection changed state");
        mock.setPolicy(bytes32(uint256(99)));
        mock.deny(t.canonicalTipBlockHash);
        require(!_advance(relay,t),"noncanonical tip accepted");
        mock.deny(bytes32(0));
        require(_advance(relay,t),"valid transition rejected");
        API.ControllerSnapshot memory snapshot=relay.controllerSnapshot();
        require(snapshot.state.checkpointHash==t.successor.checkpointHash,"wrong checkpoint");
        require(snapshot.admissionValidUntil==62,"wrong lease");
        require(snapshot.admissionValidUntil<block.timestamp,"fixture lease not expired");
        require(relay.acceptedStatements(statement),"statement missing");
        require(!_advance(relay,t),"replay accepted");
        require(relay.controllerSnapshot().state.controllerSequence==1,"replay changed state");
        return true;
    }
    function _advance(Relay relay,Relay.Transition memory t) private returns(bool ok) {
        (ok,)=address(relay).call(abi.encodeCall(Relay.advance,(t,bytes("fixture"))));
    }
}
