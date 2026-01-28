
# Reliable Bridge Transport Layer: Reliable UDP

The RBTL crate is designed around a simple idea: **you send bytes, they arrive on the other side.** This specific
implementation uses Reliable UDP ideas to have per-packet delivery guarantees.

Here's a summary of features what Reliable UDP does, specifically this crate.
(Note that Reliable UDP is not standardized, some implementations use some radically different ideas, especially
regarding encryption, congestion windows, and packet dropping logic)

| Feature | TCP | Raw UDP | Reliable UDP |
|---------|-----|---------|--------------|
| Connection-oriented? | ✅ | ❌ | ✅ |
| Message Boundaries | ❌ | ❌ | ✅ |
| Order is kept | ✅ | ❌ | ✅ Per message |
| Retransmission | ✅ Always until success | ❌ Never | ✅ Configurable per-message |
| Keep-alive | ✅ | ❌ | ✅ |
| Encryption | ❌ | ❌ | ✅ ChaCha20 with X25519 handshake |
| Timeout Detection | ✅ | ❌ No | ✅ Configurable |
| Head-of-Line Blocking | ❌ Always | ✅ Never | ✅ Never |
| Congestion handling | ✅ | ❌ | ❌ (future release) |
| Fragmentation | ✅ | ❌ | ✅ |
| Automatic Ping estimation | ❌ | ❌ | ✅ |

In summary, Reliable UDP is preferably used where **Bandwidth is plentiful but low-delay is of the utmost importance**.
For instance, Voice over IP or Real-Time Online Multiplayer Gaming.

This crate also includes automatic ping tracking, something often useful but not included in other libraries.