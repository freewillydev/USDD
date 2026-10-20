// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import {USDDInboundVaultV4 as Vault} from "../USDDInboundVaultV4.sol";
import {IControllerAcceptanceRelayV4 as API} from "../interfaces/IControllerAcceptanceRelayV4.sol";

contract VaultTokenMock {
    mapping(address=>uint256) public balanceOf;
    mapping(address=>mapping(address=>uint256)) public allowance;
    function mint(address a,uint256 n) external { balanceOf[a]+=n; }
    function approve(address a,uint256 n) external returns(bool) { allowance[msg.sender][a]=n; return true; }
    function transfer(address a,uint256 n) external returns(bool) { balanceOf[msg.sender]-=n; balanceOf[a]+=n; return true; }
    function transferFrom(address a,address b,uint256 n) external returns(bool) {
        allowance[a][msg.sender]-=n; balanceOf[a]-=n; balanceOf[b]+=n; return true;
    }
}
// Mutable test-only relay: authenticating these claims is the real relay's job.
contract VaultRelayMock {
    API.ControllerSnapshot private snapshot;
    bytes32 public inboundVaultPolicyHash;
    function securityModelId() external pure returns(bytes32) { return keccak256("USDD_V4_NO_EXPIRY_STRONG_MINED_EXECUTION"); }
    function verifierProgramId() external pure returns(bytes32) { return bytes32(uint256(1)); }
    function verifierConfigHash() external pure returns(bytes32) { return bytes32(uint256(2)); }
    function controllerSnapshot() external view returns(API.ControllerSnapshot memory) { return snapshot; }
    function set(API.ControllerSnapshot memory s) external { snapshot=s; }
    function bind(Vault v) external {
        inboundVaultPolicyHash=sha256(abi.encodePacked(bytes8("ETVPLCY2"),uint16(2),uint64(block.chainid),
            bytes32(uint256(1)),bytes32(uint256(1)),bytes32(uint256(1)),v.PROTOCOL_ID(),v.VAULT_ID(),
            address(v),address(v).codehash,bytes32(0x6c1156dbdf0e04a507f340b005bcc89bcedb92d2bee9b271e092d32f23d35ea6)));
    }
}
contract InboundVaultV4Test {
    Vault private vault;
    VaultTokenMock private token;
    VaultRelayMock private relay;
    constructor() {
        token=new VaultTokenMock(); relay=new VaultRelayMock();
        bytes32 id=bytes32(uint256(1));
        vault=new Vault(Vault.DeploymentConfig(address(token),address(relay),id,id,id,id,id,id,id,0));
        relay.bind(vault); vault.initializeControllerRelayBinding();
        token.mint(address(this),100e6); token.approve(address(vault),100e6);
    }
    function run() external returns(bool) {
        API.ControllerSnapshot memory s;
        s.state=API.AcceptanceState(bytes32(uint256(1)),bytes32(uint256(2)),bytes32(uint256(3)),
            1,0,0,bytes32(uint256(4)),1,uint64(block.timestamp),bytes32(uint256(1)),1,uint64(block.timestamp));
        s.acceptedAnchorStateCommitment=bytes32(uint256(5));
        s.acceptedAnchorExecutionCheckpointHash=bytes32(uint256(6)); s.acceptedAnchorSequence=1;
        s.acceptedAt=uint64(block.timestamp); s.admissionValidUntil=uint64(block.timestamp+2 hours);
        relay.set(s);
        (,bytes32 mintIntent)=vault.openIntent(10e6,hex"51",bytes32(uint256(1)),address(this),uint64(block.timestamp+1 days));
        vault.commitIntent(mintIntent);
        (,bytes32 cancelIntent)=vault.openIntent(20e6,hex"51",bytes32(uint256(2)),address(this),uint64(block.timestamp+1 days));
        vault.commitIntent(cancelIntent); vault.requestCancellation(cancelIntent);
        (,bytes32 pending)=vault.openIntent(5e6,hex"51",bytes32(uint256(3)),address(this),uint64(block.timestamp+1 days));
        // Delayed, already-accepted state: freshness must block new commitment,
        // but must not stop completion of a cryptographically accepted leaf.
        s.acceptedAt=uint64(block.timestamp-100);
        s.state.parentMedianTimePast=s.acceptedAt; s.state.ethereumFinalizedTimestamp=s.acceptedAt;
        s.admissionValidUntil=uint64(block.timestamp-1);
        s.state.controllerSequence=2; s.state.resolutionCount=2; s.state.nextResolutionNonce=2;
        bytes32[64] memory branch;
        bytes32 mintLeaf=vault.hashResolutionLeaf(mintIntent,Vault.ResolutionKind.Mint,0);
        bytes32 cancelLeaf=vault.hashResolutionLeaf(cancelIntent,Vault.ResolutionKind.Cancel,1);
        branch[0]=cancelLeaf;
        s.state.cumulativeResolutionRoot=vault.computeResolutionRoot(mintLeaf,0,branch);
        relay.set(s);
        (bool ok,)=address(vault).call(abi.encodeCall(Vault.commitIntent,(pending)));
        require(!ok,"expired admission accepted");
        require(vault.intentState(pending)==Vault.IntentState.Pending,"failed commit changed intent");
        branch[1]=bytes32(uint256(99));
        (ok,)=address(vault).call(abi.encodeCall(Vault.acknowledgeMint,(mintIntent,0,branch)));
        require(!ok,"bad resolution branch accepted");
        branch[1]=0; vault.acknowledgeMint(mintIntent,0,branch);
        (ok,)=address(vault).call(abi.encodeCall(Vault.acknowledgeMint,(mintIntent,0,branch)));
        require(!ok,"duplicate mint accepted");
        branch[0]=mintLeaf; vault.finalizeCancellation(cancelIntent,1,branch);
        (ok,)=address(vault).call(abi.encodeCall(Vault.finalizeCancellation,(cancelIntent,1,branch)));
        require(!ok,"duplicate cancellation accepted");
        vault.refundUncommittedIntent(pending);
        require(token.balanceOf(address(this))==90e6,"wrong refunded balance");
        require(vault.reserveBalanceUSDT6()==10e6,"reserve not 1:1");
        require(vault.accountedCustodyUSDT6()==10e6,"wrong custody accounting");
        require(vault.principalLiabilityUSDT6()==10e6,"wrong principal liability");
        require(vault.RESOLUTION_BOUNTY_USDT6()==0,"bounty changed");
        return true;
    }
}
