// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import {USDDInboundVaultV4 as Vault} from "../USDDInboundVaultV4.sol";
import {ControllerAcceptanceRelayV4 as Relay} from "../ControllerAcceptanceRelayV4.sol";
import {IControllerAcceptanceRelayV4 as API} from "../interfaces/IControllerAcceptanceRelayV4.sol";
import {ControllerAcceptanceStateCodecV4 as Codec} from "../ControllerAcceptanceStateCodecV4.sol";
import {VaultTokenMock} from "./InboundVaultV4Test.sol";
import {RelayBoundaryV4Mock} from "./ControllerRelayV4Test.sol";

// Actual relay + vault; proof, parent and anchor authentication remain fixtures.
contract JoinedCustodyV4Test {
    Vault private vault;
    Relay private relay;
    VaultTokenMock private token;
    RelayBoundaryV4Mock private boundary;
    constructor() {
        token=new VaultTokenMock(); // CREATE nonce 1
        boundary=new RelayBoundaryV4Mock(); // CREATE nonce 2
        address predicted=address(uint160(uint256(keccak256(abi.encodePacked(hex"d694",address(this),hex"04")))));
        bytes32 id=bytes32(uint256(1));
        vault=new Vault(Vault.DeploymentConfig(address(token),predicted,id,id,id,id,id,id,id,0)); // nonce 3
        bytes32 policy=sha256(abi.encodePacked(bytes8("ETVPLCY2"),uint16(2),uint64(block.chainid),
            id,id,id,vault.PROTOCOL_ID(),vault.VAULT_ID(),address(vault),address(vault).codehash,
            bytes32(0x6c1156dbdf0e04a507f340b005bcc89bcedb92d2bee9b271e092d32f23d35ea6)));
        Relay.Boundary memory b=Relay.Boundary(address(boundary),address(boundary).codehash,id,bytes32(uint256(2)));
        relay=new Relay(Relay.Config(b,b,b,bytes32(uint256(3)),bytes32(uint256(4)),policy,sha256(Codec.encode(_source())),2 hours,bytes32(uint256(99))));
        require(address(relay)==predicted,"deployment nonce mismatch");
        vault.initializeControllerRelayBinding();
        (bool ok,)=address(vault).call(abi.encodeCall(Vault.initializeControllerRelayBinding,()));
        require(!ok,"binding initialized twice");
        token.mint(address(this),100e6); token.approve(address(vault),100e6);
    }
    function _source() private view returns(API.AcceptanceState memory) {
        return API.AcceptanceState(bytes32(uint256(10)),bytes32(uint256(11)),bytes32(uint256(12)),
            0,0,0,bytes32(uint256(13)),1,uint64(block.timestamp),bytes32(uint256(1)),1,uint64(block.timestamp));
    }
    function run() external returns(bool) {
        Relay.Transition memory t;
        t.source=_source(); t.successor=_source();
        t.successor.checkpointHash=bytes32(uint256(20)); t.successor.controllerStateHash=bytes32(uint256(21));
        t.successor.controllerSequence=1; t.successor.parentBlockHash=bytes32(uint256(22));
        t.successor.parentBlockHeight=2; t.successor.parentChainwork=bytes32(uint256(2));
        t.executionCommitment=bytes32(uint256(30)); t.elementsBlockHash=bytes32(uint256(31));
        t.elementsBlockHeight=1; t.transactionId=bytes32(uint256(32));
        t.canonicalTipContextCommitment=bytes32(uint256(33)); t.canonicalTipBlockHash=bytes32(uint256(34));
        t.canonicalTipHeight=8; t.canonicalTipMedianTimePast=uint64(block.timestamp); t.canonicalTipChainwork=8;
        t.acceptedAnchorStateCommitment=bytes32(uint256(35)); t.acceptedAnchorExecutionCheckpointHash=bytes32(uint256(36));
        t.acceptedAnchorSequence=1;
        boundary.setProof(relay.transitionPublicValuesHash(t),true); relay.advance(t,hex"01");
        (,bytes32 intent)=vault.openIntent(10e6,hex"51",bytes32(uint256(1)),address(this),uint64(block.timestamp+1 days));
        vault.commitIntent(intent);
        bytes32[64] memory branch;
        bytes32 leaf=vault.hashResolutionLeaf(intent,Vault.ResolutionKind.Mint,0);
        t.source=abi.decode(abi.encode(t.successor),(API.AcceptanceState));
        t.successor.checkpointHash=bytes32(uint256(40)); t.successor.controllerStateHash=bytes32(uint256(41));
        t.successor.controllerSequence=2; t.successor.resolutionCount=1; t.successor.nextResolutionNonce=1;
        t.successor.cumulativeResolutionRoot=vault.computeResolutionRoot(leaf,0,branch);
        t.successor.parentBlockHash=bytes32(uint256(42)); t.successor.parentBlockHeight=3;
        t.successor.parentChainwork=bytes32(uint256(3));
        boundary.setProof(relay.transitionPublicValuesHash(t),false);
        (bool ok,)=address(relay).call(abi.encodeCall(Relay.advance,(t,hex"01")));
        require(!ok,"invalid proof advanced relay");
        (ok,)=address(vault).call(abi.encodeCall(Vault.acknowledgeMint,(intent,0,branch)));
        require(!ok,"unaccepted resolution consumed");
        boundary.setProof(relay.transitionPublicValuesHash(t),true); relay.advance(t,hex"01");
        vault.acknowledgeMint(intent,0,branch);
        require(vault.reserveBalanceUSDT6()==10e6 && vault.principalLiabilityUSDT6()==10e6,"custody mismatch");
        require(token.balanceOf(address(this))==90e6,"token mismatch");
        return true;
    }
}
