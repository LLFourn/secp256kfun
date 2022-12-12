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
use rand_core::RngCore;

/// A helper trait over RNGs that handle internal mutablility.
///
/// Used by the [`Synthetic`] nonce generator.
///
/// [`RngCore`] requires `self` to be mutable which is annoying in our context. This trait requires
/// the rng be able to create randomness without being mutable. The most strightforward way of doing
/// this is to use rngs instances like [`ThreadRng`] that have a `Default` implementation are and
/// seeded from the system. See [`GlobalRng`].
///
/// If you want to BYO rng you have to either implement this trait or wrap the `RngCore` in a
/// [`RefCell`] or [`Mutex`].
///
/// [`RngCore`]: rand_core::RngCore
/// [`RefCell`]: core::cell::RefCell
/// [`Mutex`]: std::sync::Mutex
/// [`ThreadRng`]: https://docs.rs/rand/latest/rand/rngs/struct.ThreadRng.html
pub trait NonceRng {
    /// Fill `bytes` with random data.
    fn fill_bytes(&self, bytes: &mut [u8]);
}

/// We implement NonceRng only for rngs we can conjure out of thin air with `Default`.
impl<R: RngCore + Default> NonceRng for GlobalRng<R> {
    fn fill_bytes(&self, bytes: &mut [u8]) {
        R::default().fill_bytes(bytes);
    }
}

impl<R: RngCore> NonceRng for core::cell::RefCell<R> {
    fn fill_bytes(&self, bytes: &mut [u8]) {
        self.borrow_mut().fill_bytes(bytes)
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl<R: RngCore> NonceRng for std::sync::Mutex<R> {
    fn fill_bytes(&self, bytes: &mut [u8]) {
        self.lock().unwrap().fill_bytes(bytes)
    }
}

/// A nonce generator that uses an RNG to mix in real randomness into the nonce
/// generation.
///
/// The rng needs to implmenet [`NonceRng`]. This is done already for
/// [`GlobalRng`].
///
/// # Examples
///
/// ```
/// use rand::rngs::ThreadRng;
/// use secp256kfun::nonce;
/// use sha2::Sha256;
/// # let my_rng = nonce::GlobalRng::<ThreadRng>::default();
/// // the usual way to use this.
/// let nonce_gen = nonce::Synthetic::<Sha256, nonce::GlobalRng<ThreadRng>>::default(); // or OsRng
/// let nonce_gen = nonce::Synthetic::<Sha256, _>::new(my_rng); // BYO rng you've implemented NonceRng for
/// ```
///
/// [BIP-340]: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
/// [`ThreadRng`]: https://docs.rs/rand/latest/rand/rngs/struct.ThreadRng.html
/// [`OsRng`]: rand_core::OsRng
/// [`GlobalRng`]: crate::nonce::GlobalRng
#[derive(Debug, Default, Clone)]
pub struct Synthetic<H, R> {
    rng: R,
    nonce_hash: H,
    aux_hash: H,
}

impl<H: Default, R: NonceRng> Synthetic<H, R> {
    /// Creates a `Synethetic` nonce generator from anything that implements [`NonceRng`].
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

/// A zero sized type that wraps an RNG that implementes
/// `Default` e.g. [`ThreadRng`]. `GlobalRng` implements
/// [`NonceRng`] and care has been taken to ensure it is `Sync`.
///
/// # Examples
/// ```
/// use rand::rngs::ThreadRng;
/// use secp256kfun::nonce::{GlobalRng, NonceRng};
/// let nonce_rng = GlobalRng::<ThreadRng>::default();
/// let mut bytes = [0u8; 32];
/// nonce_rng.fill_bytes(&mut bytes);
/// assert_ne!(bytes, [0u8; 32]);
///
/// fn is_sync<S: Sync>(x: S) -> bool {
///     true
/// }
/// assert!(is_sync(nonce_rng));
/// ```
///
/// [`ThreadRng`]: https://docs.rs/rand/latest/rand/rngs/struct.ThreadRng.html
#[derive(Debug, Default, Clone)]
pub struct GlobalRng<R> {
    // Using fn(R) ensures that it is sync even if R is not sync
    inner: PhantomData<fn(R)>,
}

/// A deterministic nonce generator.
///
/// You should prefer [`Synthetic`] since it is more robust.
/// # Example
///
/// ```
/// use secp256kfun::{
///     nonce::{Deterministic, NonceGen},
///     Tag,
/// };
/// use sha2::Sha256;
/// let nonce_gen = Deterministic::<Sha256>::default().tag(b"BIP0340");
/// ```
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
///
/// [`derive_nonce`]: crate::derive_nonce
pub trait NonceGen {
    /// The type of hash that `begin_derivation` will return.
    type Hash: Digest<OutputSize = U32>;

    /// Takes a secret [`Scalar`] and outputs a hash. Before turining this hash into the nonce, you
    /// must add a secret input and all the public inputs from the scheme into the hash. So for a
    /// signature scheme for example you would add your secret key, the message and the public key.
    fn begin_derivation(&self, secret: &Scalar) -> Self::Hash;
}

impl<H: Digest<OutputSize = U32> + Clone> NonceGen for Deterministic<H> {
    type Hash = H;
    fn begin_derivation(&self, secret: &Scalar) -> Self::Hash {
        self.nonce_hash.clone().add(secret)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, Default)]
/// Convenience type that is [`Tag`] but is not a [`NonceGen`].
pub struct NoNonces;

impl<H: Tag> Tag for Deterministic<H> {
    fn tag_vectored<'a>(self, tag: impl Iterator<Item = &'a [u8]> + Clone) -> Self {
        Self {
            nonce_hash: self
                .nonce_hash
                .tag_vectored(tag.chain(core::iter::once(b"/nonce".as_slice()))),
        }
    }
}

impl Tag for NoNonces {
    fn tag_vectored<'a>(self, _tag: impl IntoIterator<Item = &'a [u8]>) -> Self {
        self
    }
}

impl<H, R> NonceGen for Synthetic<H, R>
where
    H: Tag + Digest<OutputSize = U32> + Clone,
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
}

impl<H: Tag, R> Tag for Synthetic<H, R> {
    fn tag_vectored<'a>(self, tag: impl Iterator<Item = &'a [u8]> + Clone) -> Self {
        Self {
            nonce_hash: self
                .nonce_hash
                .tag_vectored(tag.clone().chain(core::iter::once(b"/nonce".as_slice()))),
            aux_hash: self
                .aux_hash
                .tag_vectored(tag.chain(core::iter::once(b"/aux".as_slice()))),
            rng: self.rng,
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
        let nonce_gen_1 = Deterministic::<Sha256>::default().tag(b"PROTO_ONE");
        let nonce_gen_2 = Deterministic::<Sha256>::default().tag(b"PROTO_TWO");

        let one = s!(1);
        let two = s!(2);

        assert_eq!(get_nonce!(nonce_gen_1, one), get_nonce!(nonce_gen_1, one));
        assert_ne!(get_nonce!(nonce_gen_1, one), get_nonce!(nonce_gen_1, two));
        assert_ne!(get_nonce!(nonce_gen_1, one), get_nonce!(nonce_gen_2, one));

        let app_nonce_gen_1 = nonce_gen_1.clone().tag(b"MY_APP");
        let app_nonce_gen_2 = nonce_gen_2.clone().tag(b"MY_APP");

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
        let nonce_gen_1 = Synthetic::<Sha256, GlobalRng<ThreadRng>>::default().tag(b"PROTO_ONE");

        let one = s!(1);
        assert_ne!(get_nonce!(nonce_gen_1, one), get_nonce!(nonce_gen_1, one));
    }

    #[test]
    fn derive_nonce_macros_work_with_fixed_length_data() {
        let _ = crate::derive_nonce_rng! {
            nonce_gen => Deterministic::<Sha256>::default(),
            secret => Scalar::random(&mut rand::thread_rng()),
            public => [b"a fixed length array"],
            seedable_rng => rand::rngs::StdRng,
        };

        let _ = crate::derive_nonce! {
            nonce_gen => Deterministic::<Sha256>::default(),
            secret => Scalar::random(&mut rand::thread_rng()),
            public => [b"a fixed length array"],
        };
    }
}
