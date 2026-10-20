// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title Sha256CompressionV1
/// @notice Stateless SHA-256 compression primitive for resumable byte streams.
/// @dev This exposes exactly the standard FIPS 180-4 64-byte compression step;
///      it performs no padding. Callers must bind this exact runtime code hash.
contract Sha256CompressionV1 {
    bytes private constant ROUND_CONSTANTS = hex"428a2f9871374491b5c0fbcfe9b5dba53956c25b59f111f1923f82a4ab1c5ed5d807aa9812835b01243185be550c7dc372be5d7480deb1fe9bdc06a7c19bf174e49b69c1efbe47860fc19dc6240ca1cc2de92c6f4a7484aa5cb0a9dc76f988da983e5152a831c66db00327c8bf597fc7c6e00bf3d5a7914706ca63511429296727b70a852e1b21384d2c6dfc53380d13650a7354766a0abb81c2c92e92722c85a2bfe8a1a81a664bc24b8b70c76c51a3d192e819d6990624f40e3585106aa07019a4c1161e376c082748774c34b0bcb5391c0cb34ed8aa4a5b9cca4f682e6ff3748f82ee78a5636f84c878148cc7020890befffaa4506cebbef9a3f7c67178f2";

    error InvalidBlockLength(uint256 supplied);

    function compress(bytes32 state, bytes calldata blockBytes) external pure returns (bytes32) {
        if (blockBytes.length != 64) revert InvalidBlockLength(blockBytes.length);
        uint32[64] memory words;
        for (uint256 i; i < 16; ++i) words[i] = _be32(blockBytes, i * 4);
        unchecked {
            for (uint256 i = 16; i < 64; ++i) {
                uint32 x = words[i - 15];
                uint32 y = words[i - 2];
                uint32 s0 = _rotr(x, 7) ^ _rotr(x, 18) ^ (x >> 3);
                uint32 s1 = _rotr(y, 17) ^ _rotr(y, 19) ^ (y >> 10);
                words[i] = words[i - 16] + s0 + words[i - 7] + s1;
            }

            uint32[8] memory working;
            for (uint256 i; i < 8; ++i) working[i] = _stateWord(state, i);

            bytes memory constants = ROUND_CONSTANTS;
            for (uint256 i; i < 64; ++i) {
                uint32 sum1 = _rotr(working[4], 6) ^ _rotr(working[4], 11) ^ _rotr(working[4], 25);
                uint32 choice = (working[4] & working[5]) ^ (~working[4] & working[6]);
                uint32 temporary1 =
                    working[7] + sum1 + choice + _be32Memory(constants, i * 4) + words[i];
                uint32 sum0 = _rotr(working[0], 2) ^ _rotr(working[0], 13) ^ _rotr(working[0], 22);
                uint32 majority = (working[0] & working[1]) ^ (working[0] & working[2])
                    ^ (working[1] & working[2]);
                uint32 temporary2 = sum0 + majority;
                working[7] = working[6];
                working[6] = working[5];
                working[5] = working[4];
                working[4] = working[3] + temporary1;
                working[3] = working[2];
                working[2] = working[1];
                working[1] = working[0];
                working[0] = temporary1 + temporary2;
            }

            for (uint256 i; i < 8; ++i) working[i] += _stateWord(state, i);
            return bytes32(
                (uint256(working[0]) << 224) | (uint256(working[1]) << 192)
                    | (uint256(working[2]) << 160) | (uint256(working[3]) << 128)
                    | (uint256(working[4]) << 96) | (uint256(working[5]) << 64)
                    | (uint256(working[6]) << 32) | uint256(working[7])
            );
        }
    }

    function _rotr(uint32 value, uint32 count) private pure returns (uint32) {
        unchecked {
            return (value >> count) | (value << (32 - count));
        }
    }

    function _stateWord(bytes32 state, uint256 index) private pure returns (uint32) {
        return uint32(uint256(state) >> (224 - 32 * index));
    }

    function _be32(bytes calldata value, uint256 offset) private pure returns (uint32) {
        return (uint32(uint8(value[offset])) << 24) | (uint32(uint8(value[offset + 1])) << 16)
            | (uint32(uint8(value[offset + 2])) << 8) | uint32(uint8(value[offset + 3]));
    }

    function _be32Memory(bytes memory value, uint256 offset) private pure returns (uint32) {
        return (uint32(uint8(value[offset])) << 24) | (uint32(uint8(value[offset + 1])) << 16)
            | (uint32(uint8(value[offset + 2])) << 8) | uint32(uint8(value[offset + 3]));
    }
}
