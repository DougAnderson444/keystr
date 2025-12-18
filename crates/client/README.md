# Keystr Client 

A client that uses a key log as it's identity and authentication source.



| Feature | **`Wallet`** (key_manager.rs) | **`PasskeyWallet`** (passkey_wallet.rs) |
|---------|------------------------------|----------------------------------------|
| **Platform** | ✅ Any (server, CLI, desktop, WASM) | 🌐 Browser/WASM only |
| **Key Storage** | In-memory HashMap | Hardware-backed (TouchID, YubiKey) |
| **Security** | Software keys | Hardware secure enclave |
| **Use Case** | General purpose, development, backend | User-facing browser apps |
| **Status** | ✅ **Working & Complete** | ⚠️ Disabled (needs WebAuthn API fixes) |

### **Current Configuration:**

```rust
// PasskeyWallet is disabled outside WASM targets
#[cfg(all(feature = "web", target_arch = "wasm32"))]
pub mod passkey_wallet;
```

This means:
- ✅ **`Wallet` works everywhere** (your main implementation)
- ⚠️ **`PasskeyWallet` only compiles for WASM** (specialized use case)
