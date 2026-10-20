// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ISP1VerifierV610} from "./interfaces/ISP1VerifierV610.sol";
import {IParentFinalityRelayV2} from "./interfaces/IParentFinalityRelayV2.sol";
import {AlphaRelayContinuationJournalV3 as C} from "./libraries/AlphaRelayContinuationJournalV3.sol";
import {AlphaParentMembershipJournalV3 as M} from "./libraries/AlphaParentMembershipJournalV3.sol";
import {AlphaMembershipInvalidationV3 as H} from "./libraries/AlphaMembershipInvalidationV3.sol";

/// @notice Candidate immutable Alpha relay; NOT a qualified deployment.
/// @dev Bootstrap values are a release checkpoint trust root and must be
/// independently authenticated and reviewed before deployment. No owner may
/// change the checkpoint, proof programs, circuit, binding or depth afterward.
contract AlphaParentFinalityRelayV3 is IParentFinalityRelayV2 {
    struct Parameters {
        address sp1;
        bytes32 sp1Codehash;
        bytes32 circuit;
        bytes32 reorgProgram;
        bytes32 membershipProgram;
        bytes32 binding;
        bytes32 parentIdentity;
        bytes32 bootstrapCursor;
        bytes32 bootstrapJournal;
        uint32 bootstrapHeight;
        uint32 minimumDescendants;
    }
    address public immutable SP1;
    bytes32 public immutable SP1_CODEHASH;
    bytes32 public immutable CIRCUIT;
    bytes32 public immutable REORG_PROGRAM;
    bytes32 public immutable MEMBERSHIP_PROGRAM;
    bytes32 public immutable BINDING;
    uint32 public immutable MINIMUM_DESCENDANTS;
    bytes32 public immutable override parentChainIdentity;
    bytes32 public immutable override finalityConfigHash;
    bytes32 public acceptedCursor;
    bytes32 public acceptedJournal;
    uint32 public terminalHeight;
    H.History private history;
    struct Registration { bool exists; uint256 epoch; }
    mapping(bytes32 => Registration) private memberships;
    error InvalidConfiguration();
    error InvalidUpdate();
    error InvalidProof();
    event Advanced(bytes32 indexed cursor, bytes32 journal, uint32 height, uint32 sharedHeight);
    event Registered(bytes32 indexed hash, uint32 height, uint32 mtp, uint256 work);

    constructor(Parameters memory p) {
        if (p.sp1.code.length == 0 || p.sp1Codehash == 0 || p.sp1.codehash != p.sp1Codehash
            || p.circuit == 0 || p.reorgProgram == 0 || p.membershipProgram == 0
            || p.reorgProgram == p.membershipProgram || p.binding == 0 || p.parentIdentity == 0
            || p.bootstrapCursor == 0 || p.bootstrapJournal == 0 || p.minimumDescendants == 0)
            revert InvalidConfiguration();
        SP1=p.sp1; SP1_CODEHASH=p.sp1Codehash; CIRCUIT=p.circuit;
        REORG_PROGRAM=p.reorgProgram; MEMBERSHIP_PROGRAM=p.membershipProgram;
        BINDING=p.binding; MINIMUM_DESCENDANTS=p.minimumDescendants;
        parentChainIdentity=p.parentIdentity;
        finalityConfigHash=sha256(abi.encode("USDD_ALPHA_PARENT_FINALITY_RELAY_V3",p));
        acceptedCursor=p.bootstrapCursor; acceptedJournal=p.bootstrapJournal;
        terminalHeight=p.bootstrapHeight;
        if (!_identity()) revert InvalidConfiguration();
    }
    function _identity() private view returns(bool) {
        if (SP1.codehash != SP1_CODEHASH) return false;
        (bool ok,bytes memory out)=SP1.staticcall(abi.encodeWithSelector(ISP1VerifierV610.VERIFIER_HASH.selector));
        return ok && out.length == 32 && abi.decode(out,(bytes32)) == CIRCUIT;
    }
    function _verify(bytes32 program,bytes calldata values,bytes calldata proof) private view {
        if (!_identity() || proof.length != 356 || bytes4(proof[:4]) != bytes4(CIRCUIT)) revert InvalidProof();
        (bool ok,bytes memory out)=SP1.staticcall(abi.encodeCall(ISP1VerifierV610.verifyProof,(program,values,proof)));
        if (!ok || out.length != 0) revert InvalidProof();
    }
    function advance(bytes calldata values,bytes calldata proof) external {
        C.ReorgJournal memory r=C.decodeReorg(values);
        C.Journal memory j=r.continuation;
        if (j.acceptedCursor != acceptedCursor || r.sharedHeight > terminalHeight
            || sha256(abi.encode(j.alphaProfile,j.sourceConfiguration,j.checkpointInput,
                j.checkpointProgram,j.transitionProgram)) != BINDING) revert InvalidUpdate();
        _verify(REORG_PROGRAM,values,proof);
        uint32 height;
        for (uint256 i; i<4; ++i) height |= uint32(uint8(values[502+i])) << (8*i);
        H.invalidateAbove(history,r.sharedHeight);
        acceptedCursor=j.successorCursor; acceptedJournal=j.completeAlphaJournalSha256;
        terminalHeight=height;
        emit Advanced(acceptedCursor,acceptedJournal,height,r.sharedHeight);
    }
    function register(bytes calldata values,bytes calldata proof) external {
        M.Journal memory j=M.decode(values);
        if (j.completeAlphaJournalSha256 != acceptedJournal || j.terminalHeight != terminalHeight
            || j.minimumDescendants != MINIMUM_DESCENDANTS || j.ancestorHashDisplay == 0
            || j.ancestorMtp == 0 || j.ancestorWork == 0) revert InvalidUpdate();
        _verify(MEMBERSHIP_PROGRAM,values,proof);
        memberships[keccak256(abi.encode(j.ancestorHashDisplay,uint64(j.ancestorHeight),
            uint64(j.ancestorMtp),j.ancestorWork))]=Registration(true,history.epoch);
        emit Registered(j.ancestorHashDisplay,j.ancestorHeight,j.ancestorMtp,j.ancestorWork);
    }
    function currentFinalizedHeight() external view override returns(uint64) {
        return terminalHeight >= MINIMUM_DESCENDANTS ? terminalHeight-MINIMUM_DESCENDANTS : 0;
    }
    function isFinalizedCanonical(bytes32 hash,uint64 height,uint64 mtp,uint256 work)
        external view override returns(bool)
    {
        if (!_identity() || height > terminalHeight || terminalHeight-height < MINIMUM_DESCENDANTS) return false;
        Registration memory r=memberships[keccak256(abi.encode(hash,height,mtp,work))];
        return r.exists && r.epoch >= H.lastInvalidation(history,uint32(height));
    }
}
