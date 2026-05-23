"""
Vulnerable Token Example
A deliberately vulnerable ERC-20 token for testing the auditor.
"""

VULNERABLE_TOKEN_SOURCE = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableToken {
    string public name = "VulnToken";
    string public symbol = "VT";
    uint8 public decimals = 18;
    uint256 public totalSupply;
    
    mapping(address => uint256) public balances;
    mapping(address => mapping(address => uint256)) public allowances;
    mapping(address => bool) public isBlackListed;
    
    address public owner;
    uint256 public buyFee = 5;
    uint256 public sellFee = 5;
    bool public tradingEnabled = false;
    
    constructor() {
        owner = msg.sender;
        totalSupply = 1000000 * 10**18;
        balances[msg.sender] = totalSupply;
    }
    
    // VULNERABILITY: tx.origin authentication
    modifier onlyOwner() {
        require(tx.origin == owner, "Not owner");
        _;
    }
    
    function transfer(address to, uint256 amount) public returns (bool) {
        // VULNERABILITY: Blacklist can be weaponized
        require(!isBlackListed[msg.sender], "Blacklisted");
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // VULNERABILITY: Fee manipulation
        uint256 fee = amount * buyFee / 100;
        balances[msg.sender] -= amount;
        balances[to] += (amount - fee);
        balances[owner] += fee;
        return true;
    }
    
    // VULNERABILITY: Unprotected selfdestruct
    function destroy() external {
        selfdestruct(payable(msg.sender));
    }
    
    // VULNERABILITY: Unlimited approval helper
    function approveMax(address spender) external {
        allowances[msg.sender][spender] = type(uint256).max;
    }
    
    // VULNERABILITY: Hidden mint function
    function mint(address to, uint256 amount) external {
        totalSupply += amount;
        balances[to] += amount;
    }
    
    // VULNERABILITY: Fee can be set to 100%
    function setFee(uint256 _buy, uint256 _sell) external onlyOwner {
        buyFee = _buy;
        sellFee = _sell;
    }
    
    // VULNERABILITY: Reentrancy in withdraw
    function withdraw() external {
        uint256 amount = balances[msg.sender];
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        balances[msg.sender] = 0;
    }
    
    function enableTrading() external onlyOwner {
        tradingEnabled = true;
    }
    
    // VULNERABILITY: Unchecked return value
    function batchTransfer(address[] memory recipients, uint256 amount) external {
        for (uint i = 0; i < recipients.length; i++) {
            recipients[i].call{value: amount}("");
        }
    }
}
"""


# Expected findings from this contract
EXPECTED_VULNS = [
    "reentrancy",
    "tx_origin",
    "unlimited_approval",
    "hidden_mint",
    "selfdestruct",
    "fee_manipulation",
    "unchecked_return",
    "blacklist_mechanism",
]
