// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

/**
 * @title SafeToken
 * @notice A well-secured ERC-20 token following best practices
 * @dev Use as a baseline for testing the auditor — should produce few/no findings
 */
contract SafeToken {
    string public constant name = "SafeToken";
    string public constant symbol = "SAFE";
    uint8 public constant decimals = 18;
    uint256 public immutable maxSupply;
    
    mapping(address => uint256) private _balances;
    mapping(address => mapping(address => uint256)) private _allowances;
    
    address public owner;
    bool private _locked; // Reentrancy guard
    
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    
    error InsufficientBalance(uint256 requested, uint256 available);
    error ZeroAddress();
    error Unauthorized();
    error ReentrantCall();
    
    modifier onlyOwner() {
        if (msg.sender != owner) revert Unauthorized();
        _;
    }
    
    modifier nonReentrant() {
        if (_locked) revert ReentrantCall();
        _locked = true;
        _;
        _locked = false;
    }
    
    constructor(uint256 _maxSupply) {
        owner = msg.sender;
        maxSupply = _maxSupply;
        _balances[msg.sender] = _maxSupply;
        emit Transfer(address(0), msg.sender, _maxSupply);
    }
    
    function transfer(address to, uint256 amount) external returns (bool) {
        if (to == address(0)) revert ZeroAddress();
        uint256 senderBalance = _balances[msg.sender];
        if (senderBalance < amount) revert InsufficientBalance(amount, senderBalance);
        
        unchecked {
            _balances[msg.sender] = senderBalance - amount;
        }
        _balances[to] += amount;
        
        emit Transfer(msg.sender, to, amount);
        return true;
    }
    
    function approve(address spender, uint256 amount) external returns (bool) {
        if (spender == address(0)) revert ZeroAddress();
        _allowances[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }
    
    function withdraw() external nonReentrant {
        uint256 amount = _balances[msg.sender];
        _balances[msg.sender] = 0;
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }
    
    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }
}
