// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import {USDDVaultV4 as Unified} from "../USDDVaultV4.sol";
import {USDDInboundVaultV4 as Vault} from "../USDDInboundVaultV4.sol";
import {ControllerAcceptanceRelayV4 as Relay} from "../ControllerAcceptanceRelayV4.sol";
import {IControllerAcceptanceRelayV4 as API} from "../interfaces/IControllerAcceptanceRelayV4.sol";
import {ControllerAcceptanceStateCodecV4 as Codec} from "../ControllerAcceptanceStateCodecV4.sol";
import {SP1AlphaRedemptionProofVerifierV3 as Verifier} from "../SP1AlphaRedemptionProofVerifierV3.sol";
import {VaultTokenMock} from "./InboundVaultV4Test.sol";
import {RelayBoundaryV4Mock} from "./ControllerRelayV4Test.sol";
import {AccountingSp1Mock} from "./AccountingJournalV7Test.sol";

// Actual vault, relay and redemption verifier; recursive cryptography and
// finality are test boundaries. Domain is exported BEFORE native burn execution.
contract NativeBurnVaultV7Test {
    Unified private vault;
    Relay private relay;
    Verifier private verifier;
    VaultTokenMock private token;
    RelayBoundaryV4Mock private inbound;
    AccountingSp1Mock private sp1;
    NativeParentV7Mock private parent;
    constructor(bytes32 genesis, bytes32 asset, address sp1Address, address parentAddress, address verifierAddress) {
        token = new VaultTokenMock(); // nonce 1
        inbound = new RelayBoundaryV4Mock(); // 2
        sp1 = AccountingSp1Mock(sp1Address);
        parent = NativeParentV7Mock(parentAddress);
        verifier = Verifier(verifierAddress);
        address predicted=address(uint160(uint256(keccak256(abi.encodePacked(hex"d694",address(this),hex"04")))));
        bytes32 id=bytes32(uint256(1));
        vault=new Unified(Vault.DeploymentConfig(address(token),predicted,id,id,id,id,genesis,id,asset,0),
            Unified.RedemptionConfig(address(verifier),verifier.securityModelId(),
                verifier.verifierProgramId(),verifier.verifierConfigHash())); // 3
        bytes32 policy=sha256(abi.encodePacked(bytes8("ETVPLCY2"),uint16(2),uint64(block.chainid),
            id,id,id,vault.PROTOCOL_ID(),vault.VAULT_ID(),address(vault),address(vault).codehash,
            bytes32(0x6c1156dbdf0e04a507f340b005bcc89bcedb92d2bee9b271e092d32f23d35ea6)));
        Relay.Boundary memory b=Relay.Boundary(address(inbound),address(inbound).codehash,id,bytes32(uint256(2)));
        relay=new Relay(Relay.Config(b,b,b,bytes32(uint256(3)),bytes32(uint256(4)),policy,
            sha256(Codec.encode(_source())),2 hours,bytes32(uint256(99)))); // 4
        require(address(relay)==predicted,"nonce mismatch");
        vault.initializeControllerRelayBinding();
    }
    function _source() private view returns(API.AcceptanceState memory) {
        return API.AcceptanceState(bytes32(uint256(10)),bytes32(uint256(11)),bytes32(uint256(12)),
            0,0,0,bytes32(uint256(13)),1,uint64(block.timestamp),bytes32(uint256(1)),1,uint64(block.timestamp));
    }
    function domain() external view returns(bytes32[11] memory w) {
        w[0]=bytes32(block.chainid); w[1]=bytes32(uint256(uint160(address(vault))));
        w[2]=vault.REDEMPTION_CUSTODY_ID(); w[3]=vault.VAULT_ID(); w[4]=vault.PROTOCOL_ID();
        w[5]=verifier.securityModelId(); w[6]=verifier.verifierProgramId(); w[7]=verifier.verifierConfigHash();
        w[8]=vault.ELEMENTS_GENESIS_HASH(); w[9]=vault.USDD_ASSET_ID();
        w[10]=bytes32(uint256(uint160(address(verifier))));
    }
    function run(Unified.RedemptionClaim calldata claim, bytes calldata journal) external returns(bool) {
        require(journal.length==144 && bytes32(journal[:32])==verifier.RELEASE(),"release changed");
        require(vault.redemptionStatement(claim)==bytes32(journal[32:64]),"native/vault statement mismatch");
        require(vault.computeBurnId(claim.burnTxid,claim.burnVout)==claim.burnId,"native/vault burn ID mismatch");
        uint64 amount=claim.amountUSDT6;
        token.mint(address(this),amount); token.approve(address(vault),amount);
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
        inbound.setProof(relay.transitionPublicValuesHash(t),true); relay.advance(t,hex"01");
        (,bytes32 intent)=vault.openIntent(amount,hex"51",bytes32(uint256(1)),address(this),uint64(block.timestamp+1 days));
        vault.commitIntent(intent);
        bytes32[64] memory branch;
        bytes32 leaf=vault.hashResolutionLeaf(intent,Vault.ResolutionKind.Mint,0);
        t.source=abi.decode(abi.encode(t.successor),(API.AcceptanceState));
        t.successor.checkpointHash=bytes32(uint256(40)); t.successor.controllerStateHash=bytes32(uint256(41));
        t.successor.controllerSequence=2; t.successor.resolutionCount=1; t.successor.nextResolutionNonce=1;
        t.successor.cumulativeResolutionRoot=vault.computeResolutionRoot(leaf,0,branch);
        t.successor.parentBlockHash=bytes32(uint256(42)); t.successor.parentBlockHeight=3;
        t.successor.parentChainwork=bytes32(uint256(3));
        inbound.setProof(relay.transitionPublicValuesHash(t),true); relay.advance(t,hex"01");
        vault.acknowledgeMint(intent,0,branch);
        require(vault.principalLiabilityUSDT6()==amount && vault.reserveBalanceUSDT6()==amount,"backing mismatch");
        bytes memory proof=new bytes(500);
        for(uint i;i<144;++i) proof[i]=journal[i];
        bytes4 circuit=bytes4(sp1.VERIFIER_HASH());
        for(uint i;i<4;++i) proof[144+i]=circuit[i];
        parent.setJournal(journal);
        uint256 beforeBalance=token.balanceOf(claim.recipient);
        // A failed recursive proof must leave the burn spendable and funds intact.
        (bool ok,)=address(vault).call(abi.encodeCall(Unified.redeem,(claim,proof)));
        require(!ok && !vault.spentBurnIds(claim.burnId),"failed proof consumed burn");
        sp1.setExpected(sha256(journal));
        vault.redeem(claim,proof);
        require(token.balanceOf(claim.recipient)==beforeBalance+amount,"wrong payout");
        require(vault.principalLiabilityUSDT6()==0 && vault.reserveBalanceUSDT6()==0,"remaining liability");
        require(vault.totalRedeemedUSDT6()==amount && vault.spentBurnIds(claim.burnId),"burn not accounted");
        (ok,)=address(vault).call(abi.encodeCall(Unified.redeem,(claim,proof)));
        require(!ok && token.balanceOf(claim.recipient)==beforeBalance+amount,"duplicate payout");
        return true;
    }
}
contract NativeParentV7Mock {
    bytes32 private tuple;
    function setJournal(bytes calldata journal) external {
        require(journal.length==144);
        tuple=keccak256(abi.encode(bytes32(journal[64:96]),uint64(uint32(bytes4(journal[96:100]))),
            uint64(uint32(bytes4(journal[100:104]))),uint256(bytes32(journal[104:136]))));
    }
    function parentChainIdentity() external pure returns(bytes32) { return bytes32(uint256(4)); }
    function finalityConfigHash() external pure returns(bytes32) { return bytes32(uint256(5)); }
    function isFinalizedCanonical(bytes32 hash,uint64 height,uint64 mtp,uint256 work) external view returns(bool) {
        return tuple==keccak256(abi.encode(hash,height,mtp,work));
    }
}
