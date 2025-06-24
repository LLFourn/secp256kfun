//! Our take on the WIP *[ChillDKG: Distributed Key Generation for FROST][ChillDKG]* spec
//!
//! ChillDKG is a modular distributed key generation protocol. At the end all the intended parties
//! have a valid `t-of-n` [Shamir secret sharing] of a secret key without requiring a trusted party
//! or even an honest majority.
//!
//! The [WIP spec][ChillDKG] defines two roles:
//!
//! - *Coordinator*: A central party who relays and aggregates messages between the other parties.
//! - *Participants*: The parties who provide secret input and receive secret shares as output from the protocol.
//!
//! In this implementation we split "participants" into two further roles:
//!
//! - *Contributors*: parties that provide secret input into the key generation
//! - *Receivers*: parties that receive a secret share from the protocol.
//!
//! We see a benefit to having parties that provide secret input but do not receive secret output.
//! The main example of this is having the coordinator itself be an *Contributor* too. In the context
//! of a Bitcoin hardware wallet, the coordinator is usually the only party with access to the
//! internet therefore, if the coordinator contributes input honestly, even if all the non-internet
//! connected devices are malicious the *remote* adversary (who set the code of the malicious
//! device) will not know the secret key. In fact, the adversary would have to recover `t` devices
//! and extract their internal state to reconstruct the key. This is nice, because *in theory* and
//! in this limited sense it gives the attacker no advantage from controlling the code of the
//! signing devices (anyone who wants to reconstruct the key already needs `t` shares).
//!
//! ## Variants
//!
//! The spec comes in three variants:
//!
//! - [`simplepedpop`]: bare bones FROST key generation
//! - [`encpedpop`]: Adds encryption to the secret input so the coordinator can aggregate encrypted secret shares.
//! - [`certpedpop`]: `encpedpop` where each party also certifies the output so they can cryptographically convince each other that the key generation was successful.
//!
//! [ChillDKG]: https://github.com/BlockstreamResearch/bip-frost-dkg

pub mod certpedpop;
pub mod encpedpop;
pub mod simplepedpop;

// Re-export CertificationScheme trait from certpedpop
pub use certpedpop::CertificationScheme;
