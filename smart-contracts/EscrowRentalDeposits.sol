// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * This contract assumes you are using OpenZeppelin contracts.
 *
 * In your project, install them with:
 *   npm install @openzeppelin/contracts
 *
 * Then compile with Hardhat/Foundry/Remix, etc.
 */

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract EscrowRentalDeposits is AccessControl, ReentrancyGuard, Pausable {
    using SafeERC20 for IERC20;

    // --- Roles ---
    bytes32 public constant INSPECTOR_ROLE = keccak256("INSPECTOR_ROLE");
    bytes32 public constant APPROVER_ROLE  = keccak256("APPROVER_ROLE");

    // --- Types ---

    enum State {
        None,
        Deposited,
        PendingInspection,
        Resolved
    }

    struct Violation {
        uint8 code;          // e.g. 1 = late, 2 = damage, etc.
        uint256 penalty;     // penalty amount (informational)
    }

    struct Escrow {
        address renter;      // customer wallet
        uint256 amount;      // original deposit amount
        uint256 depositedAt; // timestamp
        uint256 proposedRefund;  // set by inspector
        bytes32 evidenceHash;    // hash of evidence (off-chain photos/report)
        State state;             // lifecycle state
        uint256 proposedAt;      // time of last proposal
        Violation[] violations;  // list of violations/damages
    }

    // --- Storage ---

    IERC20 public immutable depositToken; // e.g. USDC contract
    address public feeRecipient;          // Cycle Joint wallet
    uint256 public disputeWindow;         // in seconds

    mapping(bytes32 => Escrow) private escrows;

    // --- Events ---

    event Deposited(
        bytes32 indexed bookingId,
        address indexed renter,
        uint256 amount
    );

    event InspectionStarted(
        bytes32 indexed bookingId
    );

    event OutcomeProposed(
        bytes32 indexed bookingId,
        uint256 proposedRefund,
        bytes32 evidenceHash,
        uint8[] violationCodes,
        uint256[] violationPenalties
    );

    event PayoutExecuted(
        bytes32 indexed bookingId,
        address indexed renter,
        uint256 refund,
        uint256 withheld
    );

    // --- Constructor ---

    constructor(
        IERC20 _depositToken,
        address _admin,
        address _feeRecipient,
        uint256 _disputeWindowSeconds
    ) {
        require(address(_depositToken) != address(0), "Invalid token");
        require(_admin != address(0), "Invalid admin");
        require(_feeRecipient != address(0), "Invalid fee recipient");
        require(_disputeWindowSeconds > 0, "Dispute window must be > 0");

        depositToken   = _depositToken;
        feeRecipient   = _feeRecipient;
        disputeWindow  = _disputeWindowSeconds;

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
    }

    // --- Admin functions ---

    function setFeeRecipient(address _feeRecipient)
        external
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        require(_feeRecipient != address(0), "Invalid fee recipient");
        feeRecipient = _feeRecipient;
    }

    function setDisputeWindow(uint256 _disputeWindowSeconds)
        external
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        require(_disputeWindowSeconds > 0, "Dispute window must be > 0");
        disputeWindow = _disputeWindowSeconds;
    }

    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    // --- Core logic ---

    /**
     * @notice Customer deposits funds into escrow for a specific bookingId.
     * @param bookingId A unique ID representing the rental (e.g. keccak of external ID).
     * @param amount Amount of tokens to deposit (must be pre-approved).
     */
    function deposit(bytes32 bookingId, uint256 amount)
        external
        nonReentrant
        whenNotPaused
    {
        Escrow storage e = escrows[bookingId];

        require(e.state == State.None, "Escrow already exists");
        require(amount > 0, "Amount must be > 0");

        e.renter      = msg.sender;
        e.amount      = amount;
        e.depositedAt = block.timestamp;
        e.state       = State.Deposited;

        // Pull tokens from renter into contract
        depositToken.safeTransferFrom(msg.sender, address(this), amount);

        emit Deposited(bookingId, msg.sender, amount);
    }

    /**
     * @notice Inspector marks that the bike has been returned and is pending inspection.
     */
    function markPendingInspection(bytes32 bookingId)
        external
        onlyRole(INSPECTOR_ROLE)
        whenNotPaused
    {
        Escrow storage e = escrows[bookingId];

        require(e.state == State.Deposited, "Not in Deposited state");

        e.state = State.PendingInspection;

        emit InspectionStarted(bookingId);
    }

    /**
     * @notice Inspector proposes an outcome (full/partial/no refund) plus violations.
     * @dev This can be called multiple times before approval to adjust proposal.
     */
    function proposeOutcome(
        bytes32 bookingId,
        uint256 proposedRefund,
        bytes32 evidenceHash,
        uint8[] calldata violationCodes,
        uint256[] calldata violationPenalties
    )
        external
        onlyRole(INSPECTOR_ROLE)
        whenNotPaused
    {
        Escrow storage e = escrows[bookingId];

        require(e.state == State.PendingInspection, "Not pending inspection");
        require(proposedRefund <= e.amount, "Refund exceeds deposit");
        require(
            violationCodes.length == violationPenalties.length,
            "Violation arrays mismatch"
        );

        e.proposedRefund = proposedRefund;
        e.evidenceHash   = evidenceHash;
        e.proposedAt     = block.timestamp;

        // clear previous violations (if any) and set new ones
        delete e.violations;
        for (uint256 i = 0; i < violationCodes.length; i++) {
            e.violations.push(
                Violation({
                    code: violationCodes[i],
                    penalty: violationPenalties[i]
                })
            );
        }

        emit OutcomeProposed(
            bookingId,
            proposedRefund,
            evidenceHash,
            violationCodes,
            violationPenalties
        );
    }

    /**
     * @notice Approver finalizes payout after the dispute window.
     * Funds are sent to the renter and the feeRecipient according to proposedRefund.
     */
    function approveAndPayout(bytes32 bookingId)
        external
        onlyRole(APPROVER_ROLE)
        nonReentrant
        whenNotPaused
    {
        Escrow storage e = escrows[bookingId];

        require(e.state == State.PendingInspection, "Not pending inspection");
        require(e.proposedAt != 0, "No proposed outcome");
        require(
            block.timestamp >= e.proposedAt + disputeWindow,
            "Dispute window not over"
        );
        require(e.proposedRefund <= e.amount, "Invalid proposed refund");

        uint256 total = e.amount;
        uint256 refund = e.proposedRefund;
        uint256 withheld = total - refund;

        // mark as resolved first to prevent re-entrancy on state
        e.state  = State.Resolved;
        e.amount = 0; // clear to prevent accidental reuse

        // Perform transfers
        if (refund > 0) {
            depositToken.safeTransfer(e.renter, refund);
        }
        if (withheld > 0) {
            depositToken.safeTransfer(feeRecipient, withheld);
        }

        emit PayoutExecuted(bookingId, e.renter, refund, withheld);
    }

    // --- View helpers ---

    function getEscrowBasic(bytes32 bookingId)
        external
        view
        returns (
            address renter,
            uint256 amount,
            uint256 depositedAt,
            uint256 proposedRefund,
            bytes32 evidenceHash,
            State state,
            uint256 proposedAt
        )
    {
        Escrow storage e = escrows[bookingId];
        return (
            e.renter,
            e.amount,
            e.depositedAt,
            e.proposedRefund,
            e.evidenceHash,
            e.state,
            e.proposedAt
        );
    }

    function getViolations(bytes32 bookingId)
        external
        view
        returns (Violation[] memory)
    {
        Escrow storage e = escrows[bookingId];
        return e.violations;
    }
}
