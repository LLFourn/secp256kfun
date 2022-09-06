//! Generally useful utilities related to hashing.
//!
//! In general, things in here are defined against the [`Digest`] trait from the [`RustCrypto`] project.
//!
//! [`Digest`]: digest::Digest
//! [`RustCrypto`]: https://github.com/RustCrypto/hashes
use digest::crypto_common::BlockSizeUser;

use crate::digest::{
    generic_array::typenum::{PartialDiv, Unsigned},
    Digest,
};
/// Extension trait to "tag" a hash as described in [BIP-340].
///
/// [BIP-340]: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
pub trait Tagged: Default + Clone {
    /// Returns the _tagged_ (domain separated) SHA256 instance.
    /// This is meant be used on SHA256 state with an empty buffer.
    /// # Example
    /// ```
    /// use digest::Digest;
    /// use secp256kfun::hash::Tagged;
    /// let mut hash = sha2::Sha256::default().tagged(b"my-domain/my-purpose");
    /// hash.update(b"hello world");
    /// println!("{:?}", hash.finalize());
    /// ```
    fn tagged(&self, tag: &[u8]) -> Self;
}

impl<H: BlockSizeUser + Digest + Default + Clone> Tagged for H
where
    <H as BlockSizeUser>::BlockSize: PartialDiv<H::OutputSize>,
    <<H as BlockSizeUser>::BlockSize as PartialDiv<H::OutputSize>>::Output: Unsigned,
{
    fn tagged(&self, tag: &[u8]) -> Self {
        let hashed_tag = {
            let mut hash = H::default();
            hash.update(tag);
            hash.finalize()
        };
        let mut tagged_hash = self.clone();
        let fill_block =
            <<H::BlockSize as PartialDiv<H::OutputSize>>::Output as Unsigned>::to_usize();
        for _ in 0..fill_block {
            tagged_hash.update(&hashed_tag[..]);
        }
        tagged_hash
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
/// use digest::Digest;
/// use secp256kfun::hash::{HashAdd, HashInto};
/// #[derive(Clone, Copy)]
/// struct CryptoData([u8; 42]);
///
/// impl HashInto for CryptoData {
///     fn hash_into(self, hash: &mut impl digest::Digest) {
///         hash.update(&self.0[..])
///     }
/// }
///
/// let cryptodata = CryptoData([42u8; 42]);
/// let hash = sha2::Sha256::default().add(cryptodata).finalize();
/// ```
pub trait HashInto {
    /// Asks the item to convert itself to bytes and add itself to `hash`.
    fn hash_into(self, hash: &mut impl digest::Digest);
}

impl HashInto for u8 {
    fn hash_into(self, hash: &mut impl digest::Digest) {
        hash.update(&[self])
    }
}

impl<'a, T: HashInto + Clone> HashInto for &'a T {
    fn hash_into(self, hash: &mut impl digest::Digest) {
        self.clone().hash_into(hash)
    }
}

impl<'a, T> HashInto for &'a [T]
where
    &'a T: HashInto,
{
    fn hash_into(self, hash: &mut impl digest::Digest) {
        for item in self {
            item.hash_into(hash)
        }
    }
}

impl HashInto for &str {
    fn hash_into(self, hash: &mut impl digest::Digest) {
        hash.update(self.as_bytes())
    }
}

impl<T: HashInto, const N: usize> HashInto for [T; N] {
    fn hash_into(self, hash: &mut impl digest::Digest) {
        for item in self {
            item.hash_into(hash)
        }
    }
}

/// Extension trait for [`digest::Digest`] to make adding things to the hash convenient.
pub trait HashAdd {
    /// Converts something that implements [`HashInto`] to bytes and then incorporate the result into the digest (`self`).
    fn add<HI: HashInto>(self, data: HI) -> Self;
}

impl<D: Digest> HashAdd for D {
    fn add<HI: HashInto>(mut self, data: HI) -> Self {
        data.hash_into(&mut self);
        self
    }
}
