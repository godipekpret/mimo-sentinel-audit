// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

/**
 * @title VulnerableToken
 * @notice Deliberately vulnerable contract for testing MiMo Sentinel Audit
 * @dev DO NOT deploy to mainnet — this is for educational/testing purposes only
 */
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
    
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    
    constructor() {
        owner = msg.sender;
        totalSupply = 1_000_000 * 10**18;
        balances[msg.sender] = totalSupply;
    }
    
    // VULNERABILITY: tx.origin authentication
    modifier onlyOwner() {
        require(tx.origin == owner, "Not owner");
        _;
    }
    
    function transfer(address to, uint256 amount) public returns (bool) {
        require(!isBlackListed[msg.sender], "Blacklisted");
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // VULNERABILITY: Fee manipulation (no max cap)
        uint256 fee = amount * buyFee / 100;
        balances[msg.sender] -= amount;
        balances[to] += (amount - fee);
        balances[owner] += fee;
        
        emit Transfer(msg.sender, to, amount - fee);
        return true;
    }
    
    function approve(address spender, uint256 amount) public returns (bool) {
        allowances[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }
    
    // VULNERABILITY: Reentrancy
    function withdraw() external {
        uint256 amount = balances[msg.sender];
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        balances[msg.sender] = 0;
    }
    
    // VULNERABILITY: Hidden mint
    function mint(address to, uint256 amount) external {
        totalSupply += amount;
        balances[to] += amount;
    }
    
    // VULNERABILITY: Unprotected selfdestruct
    function destroy() external {
        selfdestruct(payable(msg.sender));
    }
    
    // VULNERABILITY: Fee can be set to 100%
    function setFee(uint256 _buy, uint256 _sell) external onlyOwner {
        buyFee = _buy;
        sellFee = _sell;
    }
    
    // VULNERABILITY: Trading toggle
    function enableTrading() external onlyOwner {
        tradingEnabled = true;
    }
    
    function blacklist(address account, bool status) external onlyOwner {
        isBlackListed[account] = status;
    }
}
