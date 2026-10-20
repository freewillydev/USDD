// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IControllerAcceptanceRelayV4} from "./interfaces/IControllerAcceptanceRelayV4.sol";

/// @notice Canonical transport shared with BootstrapAcceptanceStateV4 in Rust.
/// @dev Encoding is not state validation, receipt verification or authorization.
library ControllerAcceptanceStateCodecV4 {
    function encode(IControllerAcceptanceRelayV4.AcceptanceState memory state)
        internal pure returns (bytes memory)
    {
        // Fixed-width fields, network-order integers: exactly 226 bytes.
        return bytes.concat(
            abi.encodePacked(
                bytes8("USDDAS4"), uint16(1), state.checkpointHash,
                state.controllerStateHash, state.cumulativeResolutionRoot,
                state.controllerSequence, state.resolutionCount,
                state.nextResolutionNonce
            ),
            abi.encodePacked(
                state.parentBlockHash, state.parentBlockHeight,
                state.parentMedianTimePast, state.parentChainwork,
                state.ethereumFinalizedSlot, state.ethereumFinalizedTimestamp
            )
        );
    }
}
