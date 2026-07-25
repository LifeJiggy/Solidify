# Solidity Vulnerability Test Contracts

## 1. Reentrancy — Unprotected Withdraw

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract ReentrancyBank {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 _amount) external {
        require(balances[msg.sender] >= _amount, "Insufficient balance");
        (bool ok,) = msg.sender.call{value: _amount}("");
        require(ok, "ETH transfer failed");
        balances[msg.sender] -= _amount; // state AFTER call — reentrancy
    }

    function contractBalance() external view returns (uint256) {
        return address(this).balance;
    }
}
```

---

## 2. Missing Access Control — Public Mint

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract WildMintToken {
    string public name = "WildMint";
    string public symbol = "WMT";
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    function mint(address to, uint256 amount) external {
        // @audit — no onlyOwner, no max supply cap
        balanceOf[to] += amount;
        totalSupply += amount;
    }

    function transfer(address to, uint256 amount) external {
        require(balanceOf[msg.sender] >= amount);
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
    }
}
```

---

## 3. tx.origin Authentication + Delegatecall

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract ProxyWallet {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function withdrawAll() external {
        // @audit — tx.origin instead of msg.sender
        require(tx.origin == owner, "Not owner");
        payable(msg.sender).transfer(address(this).balance);
    }

    function execute(address _target, bytes calldata _data) external {
        // @audit — unchecked delegatecall with dynamic target
        (bool ok,) = _target.delegatecall(_data);
        require(ok); // return value checked but target can be anything
    }

    receive() external payable {}
}
```

---

## 4. Integer Underflow + Unchecked Call

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0; // <-- no built-in overflow checks

contract OldToken {
    mapping(address => uint256) public balances;
    uint256 public totalSupply;

    function transfer(address to, uint256 amount) external {
        // @audit — underflow: balances[msg.sender] -= amount when amount > balance
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }

    function batchTransfer(address[] calldata recipients) external {
        for (uint256 i = 0; i < recipients.length; i++) {
            // @audit — unchecked external call + unbounded loop
            (bool sent,) = recipients[i].call("");
            sent; // unused — return value not checked
        }
    }

    function withdrawAll() external {
        // @audit — no require, sends full balance to caller
        (bool ok,) = msg.sender.call{value: address(this).balance}("");
        ok;
    }
}
```

---

## 5. Unprotected Initializer + Selfdestruct

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract UpgradeableBox {
    address public implementation;
    address public admin;
    uint256 public value;

    // @audit — no initializer modifier, anyone can call
    function initialize(address _admin) external {
        admin = _admin;
        value = 0;
    }

    function upgradeTo(address _impl) external {
        // @audit — no access control
        implementation = _impl;
    }

    function kill() external {
        // @audit — no access control, anyone can selfdestruct
        selfdestruct(payable(msg.sender));
    }

    function setValue(uint256 _v) external {
        require(msg.sender == admin, "Only admin");
        value = _v;
    }
}
```

---

## 6. Flash Loan / Oracle Manipulation — Spot Price

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function transferFrom(address, address, uint256) external returns (bool);
}

contract FlashLoanVulnerable {
    IERC20 public token;
    uint256 public reserveRatio = 50; // 50% reserve ratio

    constructor(address _token) {
        token = IERC20(_token);
    }

    function getCollateralValue(address _pool) external view returns (uint256) {
        // @audit — uses spot balance from single pool, manipulable via flash loan
        return token.balanceOf(_pool);
    }

    function borrow(uint256 _amount) external {
        // @audit — no reentrancy guard, no TWAP check
        require(
            _amount <= (token.balanceOf(address(this)) * reserveRatio) / 100,
            "Exceeds reserve"
        );
        // @audit — unchecked call
        (bool ok,) = msg.sender.call{value: _amount}("");
        ok;
    }

    function setReserveRatio(uint256 _ratio) external {
        // @audit — no access control on critical parameter
        reserveRatio = _ratio;
    }

    receive() external payable {}
}
```
