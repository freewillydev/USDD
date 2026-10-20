// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface ISuccinctM6RelayBountyView {
    function isM6Validated(bytes32 m6id) external view returns (bool);

    function proofRewardRecipient(bytes32 m6id) external view returns (address);
}

interface IUSDDVaultBountyView {
    function BIP300_REDEMPTION_VERIFIER() external view returns (address);

    function consumedM6ids(bytes32 m6id) external view returns (bool);

    function redemptionsPaidByM6id(bytes32 m6id) external view returns (uint256);
}

/// @title SuccinctM6ProverBountyV1
/// @notice Non-refundable ETH bounties for proof-bound M6 catch-up work.
/// @dev A bounty becomes earned only after the immutable relay validates the
///      target M6, the immutable vault consumes it, and the vault pays at least
///      one redemption while that M6 is its active authorization state. The
///      proof itself binds the reward recipient, preventing mempool proof theft.
///      Anyone may settle; only that proof-bound recipient may withdraw.
contract SuccinctM6ProverBountyV1 {
    ISuccinctM6RelayBountyView public immutable RELAY;
    IUSDDVaultBountyView public immutable VAULT;
    bytes32 public immutable RELAY_CODEHASH;
    bytes32 public immutable VAULT_CODEHASH;

    mapping(bytes32 m6id => uint256 amount) public bountyByM6id;
    mapping(bytes32 m6id => bool settled) public settledM6ids;
    mapping(address prover => uint256 amount) public rewardCredit;
    uint256 public totalEscrowed;
    uint256 public totalRewardCredit;

    uint256 private _reentrancyLock = 1;

    error ZeroAddress();
    error AddressHasNoCode(address target);
    error VaultRelayMismatch(address expected, address actual);
    error DependencyCodeChanged(address target, bytes32 expected, bytes32 actual);
    error ZeroM6id();
    error ZeroBounty();
    error BountyAlreadySettled(bytes32 m6id);
    error M6NotValidated(bytes32 m6id);
    error M6NotConsumedByVault(bytes32 m6id);
    error NoRedemptionPaidForM6(bytes32 m6id);
    error MissingProofRewardRecipient(bytes32 m6id);
    error NothingToWithdraw();
    error InvalidRecipient();
    error EtherTransferFailed();
    error ReentrantCall();

    event BountyFunded(bytes32 indexed m6id, address indexed funder, uint256 amount, uint256 total);
    event BountySettled(bytes32 indexed m6id, address indexed prover, uint256 amount, address settler);
    event RewardWithdrawn(address indexed prover, address indexed recipient, uint256 amount);

    constructor(address relay, address vault) {
        if (relay == address(0) || vault == address(0)) revert ZeroAddress();
        if (relay.code.length == 0) revert AddressHasNoCode(relay);
        if (vault.code.length == 0) revert AddressHasNoCode(vault);
        address vaultRelay = IUSDDVaultBountyView(vault).BIP300_REDEMPTION_VERIFIER();
        if (vaultRelay != relay) revert VaultRelayMismatch(relay, vaultRelay);

        RELAY = ISuccinctM6RelayBountyView(relay);
        VAULT = IUSDDVaultBountyView(vault);
        RELAY_CODEHASH = relay.codehash;
        VAULT_CODEHASH = vault.codehash;
    }

    /// @notice Adds a non-refundable bounty for an exact, precomputed M6id.
    function fund(bytes32 m6id) external payable {
        if (m6id == bytes32(0)) revert ZeroM6id();
        if (msg.value == 0) revert ZeroBounty();
        if (settledM6ids[m6id]) revert BountyAlreadySettled(m6id);
        bountyByM6id[m6id] += msg.value;
        totalEscrowed += msg.value;
        emit BountyFunded(m6id, msg.sender, msg.value, bountyByM6id[m6id]);
    }

    /// @notice Converts one matured bounty to pull-payment credit for the proof-bound prover.
    function settle(bytes32 m6id) external {
        _requireDependenciesUnchanged();
        if (settledM6ids[m6id]) revert BountyAlreadySettled(m6id);
        uint256 amount = bountyByM6id[m6id];
        if (amount == 0) revert ZeroBounty();
        if (!RELAY.isM6Validated(m6id)) revert M6NotValidated(m6id);
        if (!VAULT.consumedM6ids(m6id)) revert M6NotConsumedByVault(m6id);
        if (VAULT.redemptionsPaidByM6id(m6id) == 0) revert NoRedemptionPaidForM6(m6id);
        address prover = RELAY.proofRewardRecipient(m6id);
        if (prover == address(0)) revert MissingProofRewardRecipient(m6id);

        settledM6ids[m6id] = true;
        bountyByM6id[m6id] = 0;
        totalEscrowed -= amount;
        rewardCredit[prover] += amount;
        totalRewardCredit += amount;
        emit BountySettled(m6id, prover, amount, msg.sender);
    }

    /// @notice Withdraws all caller credit to a caller-selected payable address.
    function withdraw(address payable recipient) external {
        if (_reentrancyLock != 1) revert ReentrantCall();
        if (recipient == address(0) || recipient == address(this)) revert InvalidRecipient();
        uint256 amount = rewardCredit[msg.sender];
        if (amount == 0) revert NothingToWithdraw();

        _reentrancyLock = 2;
        rewardCredit[msg.sender] = 0;
        totalRewardCredit -= amount;
        (bool success,) = recipient.call{value: amount}("");
        _reentrancyLock = 1;
        if (!success) revert EtherTransferFailed();
        emit RewardWithdrawn(msg.sender, recipient, amount);
    }

    function accountedBalance() external view returns (uint256) {
        return totalEscrowed + totalRewardCredit;
    }

    function _requireDependenciesUnchanged() private view {
        bytes32 relayCodehash = address(RELAY).codehash;
        if (relayCodehash != RELAY_CODEHASH) {
            revert DependencyCodeChanged(address(RELAY), RELAY_CODEHASH, relayCodehash);
        }
        bytes32 vaultCodehash = address(VAULT).codehash;
        if (vaultCodehash != VAULT_CODEHASH) {
            revert DependencyCodeChanged(address(VAULT), VAULT_CODEHASH, vaultCodehash);
        }
    }
}
