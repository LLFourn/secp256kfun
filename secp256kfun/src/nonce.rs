//! Nonce Genration utilities
//!
//! Nonce generation is one of the most difficult things to get right when
//! implementing discrete log based cryptosystems so this library provides a
//! built-in way of doing it with sane defaults. A nonce is random secret
//! [`Scalar`] chosen per static scalar that the prover/signer takes as secret
//! input to the algorithm. For it to be secure the distribution of the nonce
//! and the public inputs to the algorithm must be _uniformly random_. For a
//! signature scheme this means for every message the nonce must appear
//! uniformly random to an attacker that does not know the corresponding secret.
//! Even a slight bias can allow an attacker to extract the secret key if they
//! can observe enough signatures/proofs.
//!
//! Implementations using secp256kfun should allow the caller to pass in a
//! [`NonceGen`] upon instantiating the scheme. When generating a nonce for a
//! secret scalar implementations should use the [`derive_nonce!`] macro.
//!
//! [`NonceGen`]: crate::nonce::NonceGen
//! [`derive_nonce!`]: crate::derive_nonce!
use crate::{hash::*, Scalar};
use core::marker::PhantomData;
use digest::{generic_array::typenum::U32, Digest};
use rand_core::{CryptoRng, RngCore};

/// A helper trait over RNGs that handle internal mutablility.
///
/// [`RngCore`] requires `self` to be mutable which is annoying in our context.
/// This trait requires the rng be able to create randomness without being
/// mutable. The most strightforward way of doing this is to use transient rngs
/// instances like [`ThreadRng`] that have a `Default` implementation. For this
/// reason, this trait is implemented for `PhantomData<ThreadRng>` (any Rng that
/// implements `Default`). If you want to BYO rng you have to implement this
/// trait yourself and handle mutability internally.
///
/// [`RngCore`]: rand_core::RngCore
/// [`ThreadRng`]: https://docs.rs/rand/latest/rand/rngs/struct.ThreadRng.html
pub trait NonceRng {
    /// Fill `bytes` with random data.
    fn fill_bytes(&self, bytes: &mut [u8]);
}

/// We implement NonceRng only for rngs we can conjure out of thin air with `Default`.
impl<R: RngCore + CryptoRng + Default> NonceRng for PhantomData<R> {
    fn fill_bytes(&self, bytes: &mut [u8]) {
        R::default().fill_bytes(bytes);
    }
}

/// A nonce generator that uses an RNG to mix in real randomness into the nonce generation.
///
/// The rng needs to implmenet [`NonceRng`]. This is done already for
/// `PhantomData<RNG>` where `RNG` is a global (specifically implements
/// `Default`) like [`OsRng`] and [`ThreadRng`].
///
/// # Example
///
/// ```
/// use rand::rngs::ThreadRng;
/// use secp256kfun::nonce;
/// use sha2::Sha256;
/// # let my_rng = core::marker::PhantomData::<ThreadRng>;
/// // the usual way to use this.
/// let nonce_gen = nonce::from_global_rng::<sha2::Sha256, ThreadRng>(); // or OsRng
/// let nonce_gen = nonce::Synthetic::<Sha256, _>::new(my_rng); // BYO rng
/// ```
/// [BIP-340]: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
/// [`ThreadRng`]: https://docs.rs/rand/latest/rand/rngs/struct.ThreadRng.html
/// [`OsRng`]: rand_core::OsRng
#[derive(Debug, Default, Clone)]
pub struct Synthetic<H, R> {
    rng: R,
    nonce_hash: H,
    aux_hash: H,
}

impl<H: Default, R: NonceRng> Synthetic<H, R> {
    /// Creates a `Synethetic` nonce generator from anything that implements [`NonceRng`]
    ///
    /// [`NonceRng`]: crate::nonce::NonceRng
    pub fn new(rng: R) -> Self {
        Self {
            rng,
            nonce_hash: H::default(),
            aux_hash: H::default(),
        }
    }
}

/// Creates a `Synthetic` nonce generotor from a _global_ rng like [`ThreadRng`] or [`OsRng`].
///
/// [`ThreadRng`]: https://docs.rs/rand/latest/rand/rngs/struct.ThreadRng.html
/// [`OsRng`]: rand_core::OsRng
///
/// # Example
///
/// ```
/// use rand::rngs::ThreadRng;
/// use secp256kfun::nonce;
/// use sha2::Sha256;
/// let nonce_gen = nonce::from_global_rng::<Sha256, ThreadRng>();
/// ```
pub fn from_global_rng<H, R>() -> Synthetic<H, PhantomData<R>>
where
    H: Default,
    R: CryptoRng + RngCore + Default,
{
    Synthetic::new(PhantomData::<R>)
}

/// A deterministic nonce generator.
///
/// You should prefer [`Synthetic`] since it is more robust.
/// # Example
///
/// ```
/// use secp256kfun::nonce::{Deterministic, NonceGen};
/// use sha2::Sha256;
/// let nonce_gen = Deterministic::<Sha256>::default()
///     .add_protocol_tag("BIP340") // for example
///     .add_application_tag("my-app");
/// ```
/// [BIP-340]: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
/// [`Synthetic`]: crate::nonce::Synthetic
#[derive(Clone, Debug, Default)]
pub struct Deterministic<H> {
    nonce_hash: H,
}

/// A trait for hash based nonce gneration.
///
/// A `NonceGen` is a type that can repeatadly be asked to inititalize a hash
/// state with `begin_derivation` that appear random for anyone who doesn't
/// know the `secret`.
///
/// There are two main implementations of this trait:
/// - [`Deterministic`]: just adds the secret to the hash and returns it.
/// - [`Synthetic`]: adds randomness into the secret before hashing it.
///
/// In general it's better to use the [`derive_nonce`] macro than to call
/// `begin_derivation` directly.
pub trait NonceGen {
    /// The type of hash that `begin_derivation` will return.
    type Hash: Digest<OutputSize = U32>;
    /// Tells the `NonceGen` to use a tag specific to a protocol.
    /// This is ensure that two similar protocols do not produce the same nonces
    /// even if they have the same public inputs. By "protocol" we mean type of cryptographic
    /// scheme. For example, for the [BIP-340] signature scheme you would use "BIP340".
    ///
    /// It is the responsibility of the protocol implementer to call this with a
    /// protocol specific tag.
    ///
    /// [BIP-340]: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
    fn add_protocol_tag(self, tag: &str) -> Self;
    /// Tells the `NonceGen` further domain separate itself for a particular
    /// application. This is useful when you are domain separating signatures in
    /// your application from other signatures **because it is crucial to change
    /// the nonces too**.
    ///
    /// For typical Fiat-Shamir type proofs/signatures there is a also
    /// [`NonceChallengeBundle`] type to help keep these in sync.
    fn add_application_tag(self, tag: &str) -> Self;
    /// Takes a secret [`Scalar`] and outputs a hash. Before turining this hash
    /// into the nonce, you must add all the public inputs from the scheme into
    /// the hash. So for a signature scheme for example you would add the
    /// message and the public key.
    fn begin_derivation(&self, secret: &Scalar) -> Self::Hash;
}

impl<H: Tagged + Digest<OutputSize = U32> + Clone> NonceGen for Deterministic<H> {
    type Hash = H;
    fn begin_derivation(&self, secret: &Scalar) -> Self::Hash {
        self.nonce_hash.clone().add(secret)
    }

    fn add_application_tag(mut self, tag: &str) -> Self {
        self.nonce_hash = self.nonce_hash.tagged(tag.as_bytes());
        self
    }

    fn add_protocol_tag(self, tag: &str) -> Self {
        Self {
            nonce_hash: self
                .nonce_hash
                .tagged(&[tag.as_bytes(), b"/nonce"].concat()),
        }
    }
}

impl<H, R> NonceGen for Synthetic<H, R>
where
    H: Tagged + Digest<OutputSize = U32> + Clone,
    R: NonceRng,
{
    type Hash = H;
    fn begin_derivation(&self, secret: &Scalar) -> Self::Hash {
        let sec_bytes = secret.to_bytes();
        let mut aux_bytes = [0u8; 32];
        self.rng.fill_bytes(&mut aux_bytes[..]);
        let mut aux_hash = self.aux_hash.clone();
        aux_hash.update(aux_bytes);
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(aux_hash.finalize().as_ref());

        // bitwise xor the hashed randomness with secret
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte ^= sec_bytes[i]
        }

        self.nonce_hash.clone().add(&bytes[..])
    }

    fn add_application_tag(mut self, tag: &str) -> Self {
        self.nonce_hash = self.nonce_hash.tagged(tag.as_bytes());
        self
    }

    fn add_protocol_tag(self, tag: &str) -> Self {
        Self {
            nonce_hash: self
                .nonce_hash
                .tagged(&[tag.as_bytes(), b"/nonce"].concat()),
            aux_hash: self.aux_hash.tagged(&[tag.as_bytes(), b"/aux"].concat()),
            rng: self.rng,
        }
    }
}

/// A struct to keep tagging of a Fiat-Shamir challenge hash and a [`NonceGen`]
/// in sync.
///
/// This exists because changing the challenge hash without changing nonce
/// generation can be a catastrophic mistake. Any time you are doing the
/// [_Fiat-Shamir_] transform you should use this. Internally this follows the
/// structure of [BIP-340] for protocol tagging so if you do:
///
/// ```
/// use rand::rngs::ThreadRng;
/// use secp256kfun::nonce;
/// use sha2::Sha256;
/// let nonce_gen = nonce::from_global_rng::<Sha256, ThreadRng>();
/// let fs = nonce::NonceChallengeBundle {
///     challenge_hash: Sha256::default(),
///     nonce_gen,
/// }
/// .add_protocol_tag("BIP340");
/// ```
/// You get a perfectly compliant [BIP-340] challenge and nonce state.
///
/// [BIP-340]: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
/// [_Fiat-Shamir_]: https://en.wikipedia.org/wiki/Fiat%E2%80%93Shamir_heuristic
#[derive(Clone, Debug, Default)]
pub struct NonceChallengeBundle<H, NG> {
    /// The challenge hash for the Fiat-Shamir based scheme.
    pub challenge_hash: H,
    /// The nonce genertor for the Firat-Shamir based scheme.
    pub nonce_gen: NG,
}

impl<NG: NonceGen, H: Tagged> NonceChallengeBundle<H, NG> {
    /// Tags both the [`NonceGen`] and the challenge hash with a protocol
    /// specific tag.
    pub fn add_protocol_tag(self, tag: &str) -> Self {
        Self {
            nonce_gen: self.nonce_gen.add_protocol_tag(tag),
            challenge_hash: self
                .challenge_hash
                .tagged(&[tag.as_bytes(), b"/challenge"].concat()),
        }
    }

    /// Tags both the [`NonceGen`] and the challenge hash with an application
    /// specific tag.
    pub fn add_application_tag(self, tag: &str) -> Self {
        Self {
            nonce_gen: self.nonce_gen.add_application_tag(tag),
            challenge_hash: self.challenge_hash.tagged(tag.as_bytes()),
        }
    }
}

/// When NonceGen is () just ignore it
impl<H: Tagged> NonceChallengeBundle<H, ()> {
    /// Only tags the challenge hash
    pub fn add_protocol_tag(self, tag: &str) -> Self {
        Self {
            nonce_gen: (),
            challenge_hash: self
                .challenge_hash
                .tagged(&[tag.as_bytes(), b"/challenge"].concat()),
        }
    }

    /// Only tags the challenge hash
    pub fn add_application_tag(self, tag: &str) -> Self {
        Self {
            nonce_gen: (),
            challenge_hash: self.challenge_hash.tagged(tag.as_bytes()),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{derive_nonce, marker::Secret, s};
    use rand::rngs::ThreadRng;
    use sha2::Sha256;

    macro_rules! get_nonce {
        ($nonce_gen:expr, $scalar:expr) => {
            derive_nonce!(
                nonce_gen => $nonce_gen,
                secret => $scalar,
                public => [b"test".as_ref()]
            )
        }
    }

    #[test]
    fn deterministic_tests() {
        use core::str::FromStr;
        let nonce_gen_1 = Deterministic::<Sha256>::default().add_protocol_tag("PROTO_ONE");
        let nonce_gen_2 = Deterministic::<Sha256>::default().add_protocol_tag("PROTO_TWO");

        let one = s!(1);
        let two = s!(2);

        assert_eq!(get_nonce!(nonce_gen_1, one), get_nonce!(nonce_gen_1, one));
        assert_ne!(get_nonce!(nonce_gen_1, one), get_nonce!(nonce_gen_1, two));
        assert_ne!(get_nonce!(nonce_gen_1, one), get_nonce!(nonce_gen_2, one));

        let app_nonce_gen_1 = nonce_gen_1.clone().add_application_tag("MY_APP");
        let app_nonce_gen_2 = nonce_gen_2.clone().add_application_tag("MY_APP");

        assert_ne!(
            get_nonce!(nonce_gen_1, one),
            get_nonce!(app_nonce_gen_1, one)
        );
        assert_ne!(
            get_nonce!(app_nonce_gen_1, one),
            get_nonce!(app_nonce_gen_2, one)
        );

        // to check we don't accidentally change deterministic nonce generation.
        assert_eq!(
            get_nonce!(nonce_gen_1, one),
            Scalar::<Secret>::from_str(
                "34f7ce653cfa8454b3463726a599ef2925736442d2d06455974d6feae9450d90"
            )
            .unwrap()
        )
    }

    #[test]
    fn synthetic_nonce_gen_is_random() {
        let nonce_gen_1 = from_global_rng::<Sha256, ThreadRng>().add_protocol_tag("PROTO_ONE");

        let one = s!(1);
        assert_ne!(get_nonce!(nonce_gen_1, one), get_nonce!(nonce_gen_1, one));
    }
}
