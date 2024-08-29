//! Generally useful utilities related to hashing.
//!
//! In general, things in here are defined against the [`digest`] crate from the [`RustCrypto`] project.
//!
//! [`RustCrypto`]: https://github.com/RustCrypto/hashes
use digest::FixedOutput;

use crate::digest::{
    crypto_common::BlockSizeUser,
    generic_array::typenum::{PartialDiv, Unsigned, U32},
};
/// Extension trait for some cryptotraphic function that can be domain separated by a tag.
/// Used for hashes and [nonce generators][`NonceGen`].
///
/// This is blanket implemented for all [`digest`] hashes where the output size divides the block
/// size using the "tagged hash" algorithm described in `[BIP340]`.
///
/// [BIP340]: https://bips.xyz/340
/// [`NonceGen`]: crate::nonce::NonceGen.
/// [`digest`]: digest
pub trait Tag: Sized {
    /// Returns the _tagged_ (domain separated) instance of `self`.
    ///
    /// When implemented on block hashes, the hashes internal buffer should be empty before calling
    /// it.
    ///
    /// # Example
    ///
    /// ```
    /// use digest::Digest;
    /// use secp256kfun::Tag;
    /// let mut hash = sha2::Sha256::default().tag(b"my-domain/my-purpose");
    /// hash.update(b"hello world");
    /// println!("{:?}", hash.finalize());
    /// ```
    fn tag(self, tag: &[u8]) -> Self {
        self.tag_vectored(core::iter::once(tag))
    }

    /// Takes a tag that is split up into pieces.
    ///
    /// ```
    /// use digest::Digest;
    /// use secp256kfun::Tag;
    /// let mut hash1 = sha2::Sha256::default()
    ///     .tag_vectored([b"my-domain".as_slice(), b"/my-purpose".as_slice()].into_iter());
    /// let mut hash2 = sha2::Sha256::default().tag(b"my-domain/my-purpose");
    /// hash1.update(b"hello world");
    /// hash2.update(b"hello world");
    /// assert_eq!(hash1.finalize(), hash2.finalize());
    /// ```
    fn tag_vectored<'a>(self, tag_components: impl Iterator<Item = &'a [u8]> + Clone) -> Self;
}

impl<H: BlockSizeUser + FixedOutput + Default + Clone> Tag for H
where
    <H as BlockSizeUser>::BlockSize: PartialDiv<H::OutputSize>,
    <<H as BlockSizeUser>::BlockSize as PartialDiv<H::OutputSize>>::Output: Unsigned,
{
    fn tag_vectored<'a>(mut self, tag_components: impl Iterator<Item = &'a [u8]> + Clone) -> Self {
        let hashed_tag = {
            let mut hash = H::default();
            for component in tag_components {
                hash.update(component);
            }
            hash.finalize_fixed()
        };
        let fill_block =
            <<H::BlockSize as PartialDiv<H::OutputSize>>::Output as Unsigned>::to_usize();
        for _ in 0..fill_block {
            self.update(&hashed_tag[..]);
        }
        self
    }
}

/// Anything that can be hashed.
///
/// The implementations of this trait decide how the type will be converted into
/// bytes so that it can be included in the hash.
///
/// # Example
///
/// ```
/// use secp256kfun::{
///     digest::{self, Digest},
///     hash::{HashAdd, HashInto},
/// };
/// #[derive(Clone, Copy)]
/// struct CryptoData([u8; 42]);
///
/// impl HashInto for CryptoData {
///     fn hash_into(self, hash: &mut impl digest::Update) {
///         hash.update(&self.0[..])
///     }
/// }
///
/// let cryptodata = CryptoData([42u8; 42]);
/// let hash = sha2::Sha256::default().add(cryptodata).finalize();
/// ```
pub trait HashInto {
    /// Asks the item to convert itself to bytes and add itself to `hash`.
    fn hash_into(self, hash: &mut impl digest::Update);
}

impl HashInto for u8 {
    fn hash_into(self, hash: &mut impl digest::Update) {
        hash.update(&[self])
    }
}

impl<'a, T: HashInto + Clone> HashInto for &'a T {
    fn hash_into(self, hash: &mut impl digest::Update) {
        self.clone().hash_into(hash)
    }
}

impl<'a, T> HashInto for &'a [T]
where
    &'a T: HashInto,
{
    fn hash_into(self, hash: &mut impl digest::Update) {
        for item in self {
            item.hash_into(hash)
        }
    }
}

impl HashInto for &str {
    fn hash_into(self, hash: &mut impl digest::Update) {
        hash.update(self.as_bytes())
    }
}

impl<T: HashInto, const N: usize> HashInto for [T; N] {
    fn hash_into(self, hash: &mut impl digest::Update) {
        for item in self {
            item.hash_into(hash)
        }
    }
}

#[cfg(feature = "alloc")]
impl<K: HashInto, V: HashInto> HashInto for alloc::collections::BTreeMap<K, V> {
    fn hash_into(self, hash: &mut impl digest::Update) {
        for (key, value) in self {
            key.hash_into(hash);
            value.hash_into(hash);
        }
    }
}

#[cfg(feature = "alloc")]
impl<T: HashInto + Ord> HashInto for alloc::collections::BTreeSet<T> {
    fn hash_into(self, hash: &mut impl digest::Update) {
        for item in self {
            item.hash_into(hash)
        }
    }
}

/// Extension trait for [`digest::Update`] to make adding things to the hash convenient.
pub trait HashAdd {
    /// Converts something that implements [`HashInto`] to bytes and then incorporate the result into the digest (`self`).
    fn add<HI: HashInto>(self, data: HI) -> Self;
}

impl<D: digest::Update> HashAdd for D {
    fn add<HI: HashInto>(mut self, data: HI) -> Self {
        data.hash_into(&mut self);
        self
    }
}

/// A convienient basket of trait impls
pub trait Hash32: digest::FixedOutput<OutputSize = U32> + Clone + Default + Tag {}

impl<H> Hash32 for H where H: digest::FixedOutput<OutputSize = U32> + Clone + Default + Tag {}
