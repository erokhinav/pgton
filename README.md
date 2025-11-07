# pgton - PostgreSQL Extension for TON Blockchain

Extension for PostgreSQL to work with TON addresses and hashes.


## Installation

```bash
sudo make install
```

```sql
psql> CREATE EXTENSION pgton;
```

## Usage Examples

### TonHash Type

The `tonhash` type stores 32-byte hash values in base64 format (44 characters).

```sql
-- Create a table with tonhash column
CREATE TABLE blocks (
    id SERIAL PRIMARY KEY,
    block_hash tonhash NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Insert hash values (base64-encoded, 44 characters)
INSERT INTO blocks (block_hash) VALUES 
    ('zc5YdF0mXW+f0K5ceUI8mR1QDu+L+aDHlVa7Rf+VbdY=');

-- Query and compare hashes
SELECT * FROM blocks WHERE block_hash = 'zc5YdF0mXW+f0K5ceUI8mR1QDu+L+aDHlVa7Rf+VbdY=';

-- Comparison operations
SELECT block_hash FROM blocks 
WHERE block_hash > 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
ORDER BY block_hash;

-- Create an index for faster lookups
CREATE INDEX idx_block_hash ON blocks(block_hash);
```

### TonAddr Type

The `tonaddr` type stores TON addresses in raw format: `workchain:address_hex`.

```sql
-- Create a table with tonaddr column
CREATE TABLE wallets (
    id SERIAL PRIMARY KEY,
    address tonaddr NOT NULL UNIQUE,
    balance BIGINT DEFAULT 0,
    last_activity TIMESTAMP
);

-- Insert addresses in raw format
INSERT INTO wallets (address, balance) VALUES 
    ('0:cdce58745d265d6f9fd0ae5c79423c991d500eef8bf9a0c79556bb45ff956dd6', 1000000000),
    ('-1:3333333333333333333333333333333333333333333333333333333333333333', 5000000000);

-- Special address types
INSERT INTO wallets (address, balance) VALUES 
    ('addr_none', 0),
    ('addr_extern', 0);

-- Query by address
SELECT * FROM wallets 
WHERE address = '0:cdce58745d265d6f9fd0ae5c79423c991d500eef8bf9a0c79556bb45ff956dd6';

-- Comparison operations
SELECT address, balance FROM wallets 
WHERE address > '0:0000000000000000000000000000000000000000000000000000000000000000'
ORDER BY address;

-- Create an index
CREATE INDEX idx_wallet_address ON wallets(address);
```

### Address Format Conversion Functions

Convert between raw and base64 address formats.

```sql
-- Convert base64 (bounceable) to raw format
SELECT base64_to_raw('EQDNzlh0XSZdb5_Qrlx5QjyZHVAO74v5oMeVVrtF_5Vt1u_o');
-- Returns: 0:cdce58745d265d6f9fd0ae5c79423c991d500eef8bf9a0c79556bb45ff956dd6

-- Convert base64 (non-bounceable) to raw format
SELECT base64_to_raw('UQDNzlh0XSZdb5_Qrlx5QjyZHVAO74v5oMeVVrtF_5Vt1rIt');
-- Returns: 0:cdce58745d265d6f9fd0ae5c79423c991d500eef8bf9a0c79556bb45ff956dd6

-- Convert raw format to base64 (bounceable)
SELECT raw_to_base64('0:cdce58745d265d6f9fd0ae5c79423c991d500eef8bf9a0c79556bb45ff956dd6');
-- Returns: EQDNzlh0XSZdb5_Qrlx5QjyZHVAO74v5oMeVVrtF_5Vt1u_o

-- Convert tonaddr column value to base64
SELECT id, tonaddr_to_base64(address) as base64_address 
FROM wallets 
WHERE address = '0:cdce58745d265d6f9fd0ae5c79423c991d500eef8bf9a0c79556bb45ff956dd6';
-- Returns: EQDNzlh0XSZdb5_Qrlx5QjyZHVAO74v5oMeVVrtF_5Vt1u_o

-- Handle special addresses
SELECT base64_to_raw('addr_none');  -- Returns: addr_none
SELECT raw_to_base64('addr_extern');  -- Returns: addr_extern
```

### Practical Query Examples

```sql
-- Create a transactions table
CREATE TABLE transactions (
    id SERIAL PRIMARY KEY,
    tx_hash tonhash NOT NULL,
    from_addr tonaddr NOT NULL,
    to_addr tonaddr NOT NULL,
    amount BIGINT NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Insert transaction with conversion from base64
INSERT INTO transactions (tx_hash, from_addr, to_addr, amount)
VALUES (
    'zc5YdF0mXW+f0K5ceUI8mR1QDu+L+aDHlVa7Rf+VbdY=',
    base64_to_raw('EQDNzlh0XSZdb5_Qrlx5QjyZHVAO74v5oMeVVrtF_5Vt1u_o')::tonaddr,
    '0:0000000000000000000000000000000000000000000000000000000000000000',
    100000000
);

-- Query transactions with address conversion
SELECT 
    id,
    tx_hash,
    tonaddr_to_base64(from_addr) as from_base64,
    tonaddr_to_base64(to_addr) as to_base64,
    amount
FROM transactions
WHERE from_addr = base64_to_raw('EQDNzlh0XSZdb5_Qrlx5QjyZHVAO74v5oMeVVrtF_5Vt1u_o')::tonaddr;

-- Join wallets with transactions
SELECT 
    w.address,
    tonaddr_to_base64(w.address) as base64_addr,
    w.balance,
    COUNT(t.id) as tx_count
FROM wallets w
LEFT JOIN transactions t ON w.address = t.from_addr
GROUP BY w.address, w.balance
HAVING COUNT(t.id) > 0;

-- Filter by address range (useful for sharding)
SELECT address, balance
FROM wallets
WHERE address >= '0:0000000000000000000000000000000000000000000000000000000000000000'
  AND address < '0:8000000000000000000000000000000000000000000000000000000000000000'
ORDER BY address;

-- Find all transactions involving a specific address (in either direction)
SELECT 
    tx_hash,
    tonaddr_to_base64(from_addr) as from_addr,
    tonaddr_to_base64(to_addr) as to_addr,
    amount,
    created_at
FROM transactions
WHERE from_addr = '0:cdce58745d265d6f9fd0ae5c79423c991d500eef8bf9a0c79556bb45ff956dd6'
   OR to_addr = '0:cdce58745d265d6f9fd0ae5c79423c991d500eef8bf9a0c79556bb45ff956dd6'
ORDER BY created_at DESC;
```

## Type Details

- **tonhash**: 32-byte hash stored as base64 (44 characters with padding)
- **tonaddr**: TON address with workchain and 32-byte address
  - Format: `workchain:address_hex` (e.g., `0:cdce...`)
  - Special values: `addr_none`, `addr_extern`
  - Supports comparison operators: `=`, `<`, `>`, `<=`, `>=`
  - Can be indexed with btree

## Functions

- `tonhash_in/out`: Input/output for tonhash type
- `tonaddr_in/out`: Input/output for tonaddr type
- `base64_to_raw(cstring)`: Convert base64 address to raw format
- `raw_to_base64(cstring)`: Convert raw address to base64 format
- `tonaddr_to_base64(tonaddr)`: Convert tonaddr value to base64 format
