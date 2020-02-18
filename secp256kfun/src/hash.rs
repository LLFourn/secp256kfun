//! hashing utilities.
use crate::Scalar;
use digest::{generic_array::typenum::U32, Digest};
use rand_core::{CryptoRng, RngCore};

/// Generates a BIP-340 tagged hash from a tag.
///
/// Returns the _tagged_ (domain separated) SHA256 instance as introduced in
/// [BIP-340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki).
///
/// # Example
/// ```
/// use digest::Digest;
/// use secp256kfun::hash::tagged_hash;
/// let mut hash = tagged_hash(b"my-domain/my-purpose");
/// hash.input(b"hello world");
/// println!("{:?}", hash.result());
/// ```
//TODO: Make this generic over any block hash
pub fn tagged_hash(tag: &[u8]) -> sha2::Sha256 {
    let hashed_tag = {
        let mut hash = sha2::Sha256::default();
        hash.input(tag);
        hash.result()
    };

    let mut tagged_hash = sha2::Sha256::default();
    tagged_hash.input(hashed_tag);
    tagged_hash.input(hashed_tag);
    tagged_hash
}

/// A trait for anything that can be hashed. The implementations of this trait
/// decide how the type will be converted into bytes so that it can be included
/// in the hash.
///
/// # Example
///
/// ```
/// use secp256kfun::hash::HashInto;
/// struct CryptoData([u8; 42]);
///
/// impl HashInto for CryptoData {
///     fn hash_into(&self, hash: &mut impl digest::Digest) {
///         hash.input(&self.0[..])
///     }
/// }
/// ```
pub trait HashInto {
    fn hash_into(&self, hash: &mut impl Digest);
}

impl HashInto for [u8] {
    fn hash_into(&self, hash: &mut impl Digest) {
        hash.input(self)
    }
}

pub trait Hash {
    fn add<HI: HashInto + ?Sized>(self, data: &HI) -> Self;
}

impl<D: Digest> Hash for D {
    fn add<HI: HashInto + ?Sized>(mut self, data: &HI) -> Self {
        data.hash_into(&mut self);
        self
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
/// A choice of nonce Derivation.
pub enum Derivation {
    /// Derive a nonce deterministically from a secret
    Deterministic,
    /// Derive a nonce with additional randomness
    Aux([u8; 32]),
}

impl Derivation {
    /// Add randomness to a nonce derivation.
    ///
    /// # Example
    ///```
    /// use secp256kfun::hash::Derivation;
    /// let derivation = Derivation::rng(&mut rand::thread_rng());
    /// ```
    pub fn rng<R: RngCore + CryptoRng>(rng: &mut R) -> Derivation {
        let mut aux = [0u8; 32];
        rng.fill_bytes(&mut aux);
        Derivation::Aux(aux)
    }
}

/// Hashes for doing nonce derivation.
///
/// Usually, libraries that use `secp256kfun` let the caller decide which type
/// of nonce [Derivation] they will use. `NonceHash` two hashes that may be needed at runtime:
///
/// - `nonce_hash`: The hash that's used to produce the secret unpredictable nonce.
/// - 'aux_hash`:   A hash that's used to hash random data before being xor'd into the nonce hash.
///
///
/// # Example
/// ```
/// use secp256kfun::{
///     hash::{tagged_hash, Derivation, NonceHash},
///     Scalar,
/// };
/// let secret_scalar = Scalar::random(&mut rand::thread_rng());
/// let nonce_hash = NonceHash {
///     nonce_hash: tagged_hash(b"my-nonce-hash"),
///     aux_hash: tagged_hash(b"my-auxiliary-random-data-hash"),
/// };
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct NonceHash<H> {
    pub nonce_hash: H,
    pub aux_hash: H,
}

impl NonceHash<sha2::Sha256> {
    /// Generate a `NonceHash` from a tag.
    /// # Example
    ///
    /// ```
    /// use digest::Digest;
    /// use secp256kfun::hash::{tagged_hash, NonceHash};
    /// let nonce_hash_1 = NonceHash::from_tag(b"my-tag");
    /// // which is equivalent to:
    /// let nonce_hash_2 = NonceHash {
    ///     nonce_hash: tagged_hash(b"my-tag/nonce"),
    ///     aux_hash: tagged_hash(b"my-tag/aux"),
    /// };
    ///
    /// assert_eq!(
    ///     nonce_hash_1.nonce_hash.clone().result(),
    ///     nonce_hash_2.nonce_hash.clone().result(),
    /// );
    /// ```
    pub fn from_tag(tag: &[u8]) -> Self {
        Self {
            nonce_hash: tagged_hash(&[tag, b"/nonce"].concat()),
            aux_hash: tagged_hash(&[tag, b"/aux"].concat()),
        }
    }
}

impl<H: Digest<OutputSize = U32> + Clone> NonceHash<H> {
    /// Create a nonce derivation hash from a given derivation and secret
    /// unpredictable scalar. Rather than use this method directly it's generally clearer
    /// to use the [`derive_nonce`](macro.derive_nonce) macro.
    ///
    /// # Examples
    ///
    /// Derive a nonce deterministically:
    /// ```
    /// # use secp256kfun::{hash::{Derivation, NonceHash, Hash}, Scalar};
    /// let nonce_hash = NonceHash::from_tag(b"test");
    /// let secret = Scalar::random(&mut rand::thread_rng());
    /// let secret_derived_nonce = Scalar::from_hash(
    ///     nonce_hash
    ///         .begin_derivation(Derivation::Deterministic, &secret)
    ///         .add(b"other data".as_ref()),
    /// );
    /// ```
    ///
    /// Derive a nonce using randomness:
    /// ```
    /// # use secp256kfun::{hash::{Derivation, NonceHash, Hash}, Scalar};
    /// # let nonce_hash = NonceHash::from_tag(b"test");
    /// # let secret = Scalar::random(&mut rand::thread_rng());
    /// let secret_derived_nonce = Scalar::from_hash(
    ///     nonce_hash
    ///         .begin_derivation(Derivation::rng(&mut rand::thread_rng()), &secret)
    ///         .add(b"other data".as_ref()),
    /// );
    /// ```
    ///
    /// The above is a convenient form of:
    ///
    /// ```
    /// # use secp256kfun::{hash::{Derivation, NonceHash, Hash}, Scalar};
    /// # use rand_core::RngCore;
    /// # let nonce_hash = NonceHash::from_tag(b"test");
    /// # let secret = Scalar::random(&mut rand::thread_rng());
    /// let mut aux = [0u8; 32];
    /// rand::thread_rng().fill_bytes(&mut aux);
    /// let secret_derived_nonce = Scalar::from_hash(
    ///     nonce_hash
    ///         .begin_derivation(Derivation::Aux(aux), &secret)
    ///         .add(b"other data".as_ref()),
    /// );
    /// ```
    pub fn begin_derivation(&self, derivation: Derivation, secret: &Scalar) -> H {
        match derivation {
            Derivation::Deterministic => self.nonce_hash.clone().add(secret),
            Derivation::Aux(aux_bytes) => {
                let sec_bytes = secret.to_bytes();
                let mut aux_hash = self.aux_hash.clone();
                aux_hash.input(aux_bytes);
                let mut bytes = [0u8; 32];
                bytes.copy_from_slice(aux_hash.result().as_ref());

                // bitwise xor the hashed randomness with secret
                for (i, byte) in bytes.iter_mut().enumerate() {
                    *byte ^= sec_bytes[i]
                }

                self.nonce_hash.clone().add(&bytes[..])
            }
        }
    }
}
