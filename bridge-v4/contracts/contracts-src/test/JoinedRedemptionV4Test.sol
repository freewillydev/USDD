// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import {USDDVaultV4 as Unified} from "../USDDVaultV4.sol";
import {USDDInboundVaultV4 as Vault} from "../USDDInboundVaultV4.sol";
import {ControllerAcceptanceRelayV4 as Relay} from "../ControllerAcceptanceRelayV4.sol";
import {IControllerAcceptanceRelayV4 as API} from "../interfaces/IControllerAcceptanceRelayV4.sol";
import {ControllerAcceptanceStateCodecV4 as Codec} from "../ControllerAcceptanceStateCodecV4.sol";
import {VaultTokenMock} from "./InboundVaultV4Test.sol";
import {RelayBoundaryV4Mock} from "./ControllerRelayV4Test.sol";

// Actual relay + vault; proof, parent and anchor authentication remain fixtures.
contract JoinedRedemptionV4Test {
    Unified private unified;
    RedemptionBoundaryV4Mock private redemption;
    Vault private vault;
    Relay private relay;
    VaultTokenMock private token;
    RelayBoundaryV4Mock private boundary;
    constructor() {
        token=new VaultTokenMock(); // CREATE nonce 1
        boundary=new RelayBoundaryV4Mock(); // CREATE nonce 2
        address predicted=address(uint160(uint256(keccak256(abi.encodePacked(hex"d694",address(this),hex"05")))));
        bytes32 id=bytes32(uint256(1));
        redemption=new RedemptionBoundaryV4Mock(); // nonce 3
        unified=new Unified(Vault.DeploymentConfig(address(token),predicted,id,id,id,id,id,id,id,0),
            Unified.RedemptionConfig(address(redemption),redemption.securityModelId(),id,id)); // nonce 4
        vault=Vault(address(unified));
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
    // ABI words from the actual deployment, consumed by the Rust encoder.
    // Claims are synthetic codec vectors, not authenticated burn evidence.
    function redemptionVector(uint64 seed) external view returns(bytes32[20] memory w) {
        Unified.RedemptionClaim memory c=Unified.RedemptionClaim(2,unified.REDEMPTION_CUSTODY_ID(),
            bytes32(uint256(1)),bytes32(uint256(1)),sha256(abi.encodePacked("burn",seed)),uint32(seed),
            bytes32(0),seed,address(uint160(uint256(sha256(abi.encodePacked("recipient",seed))))),
            sha256(abi.encodePacked("m6",seed)),sha256(abi.encodePacked("child",seed)),
            sha256(abi.encodePacked("parent",seed)));
        c.burnId=unified.computeBurnId(c.burnTxid,c.burnVout);
        w[0]=bytes32(block.chainid); w[1]=bytes32(uint256(uint160(address(unified))));
        w[2]=unified.REDEMPTION_CUSTODY_ID(); w[3]=vault.VAULT_ID(); w[4]=vault.PROTOCOL_ID();
        w[5]=unified.REDEMPTION_SECURITY_MODEL_ID(); w[6]=unified.REDEMPTION_VERIFIER_PROGRAM_ID();
        w[7]=unified.REDEMPTION_VERIFIER_CONFIG_HASH(); w[8]=c.elementsGenesisHash; w[9]=c.usddAssetId;
        w[10]=bytes32(uint256(uint160(address(redemption))));
        w[11]=c.burnTxid; w[12]=bytes32(uint256(c.burnVout)); w[13]=c.burnId;
        w[14]=bytes32(uint256(c.amountUSDT6)); w[15]=bytes32(uint256(uint160(c.recipient)));
        w[16]=c.approvedM6id; w[17]=c.elementsExecutionCheckpointCommitment;
        w[18]=c.parentReplayCheckpointCommitment; w[19]=unified.redemptionStatement(c);
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
        Unified.RedemptionClaim memory claim=Unified.RedemptionClaim(2,unified.REDEMPTION_CUSTODY_ID(),
            bytes32(uint256(1)),bytes32(uint256(1)),bytes32(uint256(70)),0,
            unified.computeBurnId(bytes32(uint256(70)),0),10e6,address(this),bytes32(uint256(71)),
            bytes32(uint256(72)),bytes32(uint256(73)));
        bytes32 statement=unified.redemptionStatement(claim);
        redemption.setStatement(statement,false);
        (ok,)=address(unified).call(abi.encodeCall(Unified.redeem,(claim,hex"01")));
        require(!ok && vault.principalLiabilityUSDT6()==10e6,"bad proof altered liabilities");
        redemption.setStatement(statement,true);
        Unified.RedemptionClaim memory altered=abi.decode(abi.encode(claim),(Unified.RedemptionClaim));
        altered.recipient=address(123);
        (ok,)=address(unified).call(abi.encodeCall(Unified.redeem,(altered,hex"01")));
        require(!ok,"recipient substitution accepted");
        altered=abi.decode(abi.encode(claim),(Unified.RedemptionClaim));
        altered.amountUSDT6=11e6;
        redemption.setStatement(unified.redemptionStatement(altered),true);
        (ok,)=address(unified).call(abi.encodeCall(Unified.redeem,(altered,hex"01")));
        require(!ok && !unified.spentBurnIds(claim.burnId),"unbacked burn consumed");
        require(vault.principalLiabilityUSDT6()==10e6,"unbacked burn changed liability");
        claim.amountUSDT6=4e6;
        redemption.setStatement(unified.redemptionStatement(claim),true);
        unified.redeem(claim,hex"01");
        require(vault.reserveBalanceUSDT6()==6e6 && vault.principalLiabilityUSDT6()==6e6,"partial liabilities");
        require(token.balanceOf(address(this))==94e6 && unified.totalRedeemedUSDT6()==4e6,"partial payout");
        (ok,)=address(unified).call(abi.encodeCall(Unified.redeem,(claim,hex"01")));
        require(!ok && token.balanceOf(address(this))==94e6,"partial duplicate paid");
        claim.burnTxid=bytes32(uint256(74));
        claim.burnId=unified.computeBurnId(claim.burnTxid,0);
        claim.amountUSDT6=6e6;
        redemption.setStatement(unified.redemptionStatement(claim),true);
        unified.redeem(claim,hex"01");
        require(vault.reserveBalanceUSDT6()==0 && vault.principalLiabilityUSDT6()==0,"redemption liabilities");
        require(token.balanceOf(address(this))==100e6 && unified.totalRedeemedUSDT6()==10e6,"payout mismatch");
        require(unified.spentBurnIds(claim.burnId),"burn not consumed");
        require(unified.redemptionsPaidByM6id(claim.approvedM6id)==2,"M6 payment count");
        (ok,)=address(unified).call(abi.encodeCall(Unified.redeem,(claim,hex"01")));
        require(!ok && token.balanceOf(address(this))==100e6,"duplicate paid");
        return true;
    }
}

contract RedemptionBoundaryV4Mock {
    bytes32 private expected;
    bool private accepted;
    function securityModelId() external pure returns(bytes32) {
        return keccak256("USDD_ELEMENTS_BURN_SLOT24_SIX_NET_ACKS_V1");
    }
    function verifierProgramId() external pure returns(bytes32) { return bytes32(uint256(1)); }
    function verifierConfigHash() external pure returns(bytes32) { return bytes32(uint256(1)); }
    function setStatement(bytes32 statement,bool result) external { expected=statement; accepted=result; }
    function verify(bytes32 statement,bytes calldata) external view returns(bool) {
        return accepted && statement==expected;
    }
}
