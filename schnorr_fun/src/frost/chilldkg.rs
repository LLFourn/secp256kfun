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
//! We see a benefit to having parties that provide secret input but do not receive secret output —
//! we call these *aux contributors* (and the parties that do both *receiver-contributors*; every
//! receiver is also a contributor by protocol invariant). The main example of an aux contributor
//! is the coordinator itself. In the context of a Bitcoin hardware wallet, the coordinator is
//! usually the only party with access to the internet therefore, if the coordinator contributes
//! input honestly, even if all the non-internet connected devices are malicious the *remote*
//! adversary (who set the code of the malicious device) will not know the secret key. In fact,
//! the adversary would have to recover `t` devices and extract their internal state to
//! reconstruct the key. This is nice, because *in theory* and in this limited sense it gives the
//! attacker no advantage from controlling the code of the signing devices (anyone who wants to
//! reconstruct the key already needs `t` shares).
//!
//! ## Variants
//!
//! The spec comes in three variants. Most applications want [`certpedpop`].
//!
//! - [`simplepedpop`]: bare-bones FROST key generation. The application is responsible
//!   for transporting per-receiver secret shares out-of-band and for confirming all parties
//!   agree on the result.
//! - [`encpedpop`]: adds share encryption so the coordinator can aggregate encrypted shares
//!   into a single message. The application still has to confirm agreement.
//! - [`certpedpop`]: adds certification, so once the protocol completes every party holds a
//!   cryptographic proof that everyone else certified the same result.
//!
//! ## Lifecycle
//!
//! Each layer follows the same pipeline:
//!
//! 1. Each contributor calls `Contributor::gen_keygen_input` and sends the resulting
//!    `KeygenInput` to the coordinator.
//! 2. The coordinator collects inputs via `Coordinator::add_input`/`finish` and broadcasts
//!    the resulting `AggKeygenInput` back.
//! 3. Each contributor calls `verify_agg_input` to obtain a `VerifiedAggKeygenInput`.
//!    Receivers also extract their secret share at this step. In `certpedpop`, a
//!    certificate from every party must be collected before the share is released.
//!
//! ## Roles
//!
//! Use [`ShareReceiver`] (a contributor that also receives a share) or [`AuxContributor`]
//! (a contributor-only party, e.g. an internet-connected coordinator) as the type
//! parameter `R` on the layered `Contributor<R>` types. Pick the role with turbofish at
//! the call site, e.g.
//! `Contributor::<ShareReceiver>::gen_keygen_input(...)`.
//!
//! [ChillDKG]: https://github.com/BlockstreamResearch/bip-frost-dkg

pub mod certpedpop;
pub mod encpedpop;
pub mod simplepedpop;

// Re-export CertificationScheme trait from certpedpop
pub use certpedpop::CertificationScheme;

/// The role a contributor plays in the protocol. Implemented by
/// [`ShareReceiver`] and [`AuxContributor`]; sealed so no other types can.
///
/// Picked via turbofish on `Contributor<R>::gen_keygen_input` at every layer.
pub trait Role: simplepedpop::role_sealed::Sealed {}

/// A contributor that also receives a secret share. The main case: a participant
/// (e.g. a hardware wallet) that contributes entropy and gets a share back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShareReceiver;

/// A contributor that does not receive a share. The main case: an
/// internet-connected coordinator that contributes entropy so a remote attacker
/// who controls every receiver still cannot reconstruct the key without
/// physical access to `t` devices.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuxContributor;

impl Role for ShareReceiver {}
impl Role for AuxContributor {}

/// Identifies a contributor by role-relative index. Use this anywhere the API
/// asks for a party — the absolute slot translation is the protocol's job.
///
/// `Receiver(i)` is the receiver at slot `i` (`i < n_receivers`).
/// `AuxContributor(i)` is the aux at offset `i` (`i < n_aux_contributors`).
/// Ordering matches absolute slot order: every `Receiver` precedes every
/// `AuxContributor`, and within each variant the inner index orders.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Party {
    /// A share-receiving contributor at receiver-slot `i`.
    Receiver(u32),
    /// A contributor-only party at aux-slot `i`.
    AuxContributor(u32),
}

impl Party {
    /// Translate to the absolute slot index in `[0..n_contributors)`. Used
    /// internally where a positional index is required (PoP signing/verifying,
    /// indexing into per-slot vectors).
    pub fn slot_index(self, n_receivers: u32) -> u32 {
        match self {
            Party::Receiver(i) => i,
            Party::AuxContributor(i) => n_receivers + i,
        }
    }
}
