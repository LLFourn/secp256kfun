//! Generally useful utilities related to hashing.
//!
//! In general, things in here are defined against the [`Digest`] trait from the [`RustCrypto`] project.
//!
//! [`Digest`]: digest::Digest
//! [`RustCrypto`]: https://github.com/RustCrypto/hashes
use crate::digest::{
    generic_array::typenum::{PartialDiv, Unsigned},
    BlockInput, Digest,
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

impl<H: BlockInput + Digest + Default + Clone> Tagged for H
where
    <H as BlockInput>::BlockSize: PartialDiv<H::OutputSize>,
    <<H as BlockInput>::BlockSize as PartialDiv<H::OutputSize>>::Output: Unsigned,
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
/// struct CryptoData([u8; 42]);
///
/// impl HashInto for CryptoData {
///     fn hash_into(&self, hash: &mut impl digest::Digest) {
///         hash.update(&self.0[..])
///     }
/// }
///
/// let cryptodata = CryptoData([42u8; 42]);
/// let hash = sha2::Sha256::default().add(&cryptodata).finalize();
/// ```
pub trait HashInto {
    /// Asks the item to convert itself to bytes and add itself to `hash`.
    fn hash_into(&self, hash: &mut impl digest::Digest);
}

impl HashInto for [u8] {
    fn hash_into(&self, hash: &mut impl digest::Digest) {
        hash.update(self)
    }
}

impl HashInto for str {
    fn hash_into(&self, hash: &mut impl digest::Digest) {
        hash.update(self.as_bytes())
    }
}

/// Extension trait for [`digest::Digest`] to make adding things to the hash convenient.
pub trait HashAdd {
    /// Converts something that implements [`HashInto`] to bytes and then incorporate the result into the digest (`self`).
    fn add<HI: HashInto + ?Sized>(self, data: &HI) -> Self;
}

impl<D: Digest> HashAdd for D {
    fn add<HI: HashInto + ?Sized>(mut self, data: &HI) -> Self {
        data.hash_into(&mut self);
        self
    }
}

/// Trait for things that can domain separate themselves.
///
/// i.e. given a protocol or application tag can produce a new version that will
/// not give the same outputs for a given input if the tags are different.
pub trait AddTag {
    /// Tells the invocant to return a new version of itself modifies with the
    /// protocol tag. This is to ensure that the `AddTag` does not produce the
    /// same outputs for tow different protocols even if they have the same
    /// public inputs. By "protocol" we mean type of cryptographic scheme. For
    /// example, for the [BIP-340] signature scheme you would use "BIP340" as
    /// the tag.
    ///
    /// [BIP-340]: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
    fn add_protocol_tag(self, tag: &str) -> Self;
    /// Tells the `AddTag` to further domain separate itself for a particular
    /// application. This is useful when you are domain separating signatures in
    /// your application from other signatures.
    fn add_application_tag(self, tag: &str) -> Self;
}

/// AddTag is implemented for () so you can use implement things generically for
/// `AddTag` even for things that have some field set to () (for example
/// `NonceGen` when you're doing verification only).
impl AddTag for () {
    fn add_protocol_tag(self, _tag: &str) -> Self {
        ()
    }
    fn add_application_tag(self, _tag: &str) -> Self {
        ()
    }
}
