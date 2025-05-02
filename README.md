# 🔐 AuthOnChain

A Solidity smart contract for decentralized, on-chain authentication. This contract is designed to manage user identity and session control directly on the Ethereum blockchain, providing a foundation for Web3-native passwordless authentication systems.

---

## ✨ Features

- **User Registration**: Users can register with a public identifier (e.g., wallet address or DID).
- **On-chain Session Management**: Sessions can be created, validated, and expired directly on-chain.
- **Decentralized Authentication**: No reliance on centralized servers for login or identity.

---

## 📄 Contract Overview

### `AuthOnChain.sol`

- Core contract to manage users and sessions.
- Tracks registered users.
- Issues session tokens or flags tied to Ethereum addresses.

---