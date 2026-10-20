use thiserror::Error;

/// Errors are intentionally stable, compact, and independent of host I/O.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ProtocolError {
    #[error("arithmetic overflow")]
    ArithmeticOverflow,
    #[error("division by zero")]
    DivisionByZero,
    #[error("non-canonical encoding")]
    NonCanonicalEncoding,
    #[error("private leaf salt must be non-zero")]
    ZeroSalt,
    #[error("unexpected end of encoding")]
    UnexpectedEnd,
    #[error("trailing bytes in encoding")]
    TrailingBytes,
    #[error("invalid enum discriminant {0}")]
    InvalidDiscriminant(u8),
    #[error("invalid price")]
    InvalidPrice,
    #[error("invalid quantity")]
    InvalidQuantity,
    #[error("invalid market")]
    InvalidMarket,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("signing key does not match trader key")]
    SigningKeyMismatch,
    #[error("order is not live at the requested height")]
    OrderNotLive,
    #[error("order nonce does not match the account nonce")]
    InvalidNonce,
    #[error("order would increase a reduce-only position")]
    ReduceOnlyViolation,
    #[error("orders have incompatible sides, prices, markets, or chain ids")]
    IncompatibleOrders,
    #[error("fill quantity exceeds an order or position limit")]
    ExcessFill,
    #[error("fee or margin rate is outside the protocol range")]
    InvalidRate,
    #[error("account has insufficient collateral")]
    InsufficientCollateral,
    #[error("account is not liquidatable")]
    NotLiquidatable,
    #[error("duplicate Merkle key")]
    DuplicateMerkleKey,
    #[error("invalid Merkle proof")]
    InvalidMerkleProof,
    #[error("state root mismatch")]
    StateRootMismatch,
    #[error("state sequence must advance by exactly one")]
    InvalidStateSequence,
    #[error("batch hash mismatch")]
    BatchHashMismatch,
    #[error("transition field mismatch: {0}")]
    TransitionMismatch(&'static str),
    #[error("duplicate or previously consumed request")]
    DuplicateRequest,
    #[error("trade sequences decrease or reuse a sequence for another taker")]
    InvalidTradeSequence,
    #[error("fill violates committed price-time priority")]
    PriceTimePriorityViolation,
    #[error("risk parameter commitment mismatch")]
    RiskParamsMismatch,
    #[error("invalid oracle configuration")]
    InvalidOracleConfiguration,
    #[error("invalid oracle source")]
    InvalidOracleSource,
    #[error("invalid oracle schedule")]
    InvalidOracleSchedule,
    #[error("invalid oracle snapshot")]
    InvalidOracleSnapshot,
    #[error("invalid Truthcoin anchor state")]
    InvalidTruthcoinAnchor,
    #[error("invalid Truthcoin anchor successor")]
    InvalidTruthcoinAnchorSuccessor,
    #[error("invalid USDD finalized-Ethereum checkpoint")]
    InvalidUsddCheckpoint,
    #[error("invalid USDD finalized-Ethereum checkpoint successor")]
    InvalidUsddCheckpointSuccessor,
    #[error("invalid central matcher configuration")]
    InvalidCentralMatcherConfiguration,
    #[error("invalid encrypted-witness availability configuration")]
    InvalidAvailabilityConfiguration,
    #[error("invalid matcher receipt")]
    InvalidMatcherReceipt,
    #[error("invalid forced action")]
    InvalidForcedAction,
    #[error("invalid forced-action inbox transition")]
    InvalidForcedInbox,
    #[error("an overdue forced action was not consumed")]
    ForcedActionDeadline,
    #[error("invalid deposit inbox transition or marker")]
    InvalidDepositInbox,
    #[error("an overdue deposit was not consumed")]
    DepositDeadline,
    #[error("deposit root mismatch")]
    DepositRootMismatch,
    #[error("withdrawal root mismatch")]
    WithdrawalRootMismatch,
    #[error("withdrawal commitment mismatch")]
    WithdrawalCommitmentMismatch,
    #[error("state transition violates conservation")]
    ConservationViolation,
    #[error("invalid deterministic funding state or observation")]
    InvalidFundingState,
    #[error("invalid insurance-bond state or action")]
    InvalidBondState,
    #[error("invalid confidential bond inbox transition or marker")]
    InvalidBondInbox,
    #[error("an overdue confidential bond inbox action was not consumed")]
    BondInboxDeadline,
    #[error("unsupported protocol version")]
    UnsupportedVersion,
    #[error("wrong BMM slot")]
    WrongBmmSlot,
    #[error("malformed PXST marker")]
    MalformedPxstMarker,
    #[error("invalid authenticated child checkpoint for PXST commitment")]
    InvalidWithdrawalStateAnchor,
    #[error("Elements withdrawal bundle does not contain the one exact state marker")]
    WithdrawalStateApprovalMismatch,
}
