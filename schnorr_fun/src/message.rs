use secp256kfun::{
    Slice,
    digest::{self},
    hash::HashInto,
    marker::*,
};

/// A message to be signed.
///
/// The `S` parameter is a [`Secrecy`] which is used when signing a verifying to check whether the
/// challenge scalar produced with the message should be secret.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Message<'a, S = Public> {
    /// The message bytes
    pub bytes: Slice<'a, S>,
    /// The optional application tag to separate the signature from other applications.
    #[deprecated(
        since = "0.11.0",
        note = "Use Message::new for BIP340-style domain separation"
    )]
    pub app_tag: Option<&'static str>,
    /// The domain separator for [BIP340]-style domain separation (33-byte prefix)
    ///
    /// [BIP340]: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
    pub bip340_domain_sep: Option<&'static str>,
}

#[allow(deprecated)]
impl<'a, S: Secrecy> Message<'a, S> {
    /// Create a raw message with no domain separation. The message bytes will be passed straight into the
    /// challenge hash. Usually, you only use this when signing a pre-hashed message.
    pub fn raw(bytes: &'a [u8]) -> Self {
        Message {
            bytes: Slice::from(bytes),
            app_tag: None,
            bip340_domain_sep: None,
        }
    }

    /// Create an empty zero byte message.
    pub fn empty() -> Self {
        Self::raw(&[])
    }

    /// Create a message with [BIP340]-style domain separation using a 33-byte prefix.
    ///
    /// The domain separator will be padded with null bytes to exactly 33 bytes and
    /// prefixed to the message, as recommended in [BIP340] for domain separation.
    ///
    /// [BIP340]: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
    ///
    /// # Example
    /// ```
    /// use schnorr_fun::{Message, fun::marker::Public};
    /// let message = Message::<Public>::new("my-app/sign", b"hello world");
    /// ```
    pub fn new(domain_sep: &'static str, bytes: &'a [u8]) -> Self {
        assert!(!domain_sep.is_empty(), "domain separator must not be empty");
        assert!(
            domain_sep.len() <= 33,
            "domain separator must be 33 bytes or less"
        );
        Message {
            bytes: Slice::from(bytes),
            app_tag: None,
            bip340_domain_sep: Some(domain_sep),
        }
    }

    /// Signs a plain variable length message.
    ///
    /// You must provide an application tag to make sure signatures valid in one context are not
    /// valid in another. The tag is used as described [here].
    ///
    /// **Deprecation Note**: This method was implemented before [BIP340] had finalized its
    /// recommendation for domain separation. [BIP340] now recommends using a 33-byte padded
    /// prefix instead of the 64-byte prefix used by this method. Use [`Message::new`] instead,
    /// which implements the [BIP340]-compliant domain separation.
    ///
    /// [BIP340]: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
    ///
    /// [here]: https://github.com/sipa/bips/issues/207#issuecomment-673681901
    #[deprecated(
        since = "0.12.0",
        note = "Use Message::new for BIP340-style domain separation. This method uses a 64-byte prefix which predates the BIP340 specification."
    )]
    pub fn plain(app_tag: &'static str, bytes: &'a [u8]) -> Self {
        assert!(app_tag.len() <= 64, "tag must be 64 bytes or less");
        assert!(!app_tag.is_empty(), "tag must not be empty");
        Message {
            bytes: Slice::from(bytes),
            app_tag: Some(app_tag),
            bip340_domain_sep: None,
        }
    }

    /// Check if the message is empty with zero length
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Length of the message as it is hashed
    pub fn len(&self) -> usize {
        match (self.app_tag, self.bip340_domain_sep) {
            (Some(_), _) => 64 + self.bytes.as_inner().len(),
            (_, Some(_)) => 33 + self.bytes.as_inner().len(), // BIP340 style uses 33-byte prefix
            (None, None) => self.bytes.as_inner().len(),
        }
    }
}

#[allow(deprecated)]
impl<S> HashInto for Message<'_, S> {
    fn hash_into(self, hash: &mut impl digest::Update) {
        if let Some(prefix) = self.app_tag {
            let mut padded_prefix = [0u8; 64];
            padded_prefix[..prefix.len()].copy_from_slice(prefix.as_bytes());
            hash.update(&padded_prefix);
        } else if let Some(domain_sep) = self.bip340_domain_sep {
            // BIP340-style domain separation: 33-byte prefix
            let mut padded_prefix = [0u8; 33];
            padded_prefix[..domain_sep.len()].copy_from_slice(domain_sep.as_bytes());
            hash.update(&padded_prefix);
        }
        hash.update(self.bytes.as_inner());
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn bip340_domain_separation() {
        // Test that BIP340 domain separation uses 33-byte prefix
        let msg = Message::<Public>::new("test", b"hello");

        // Expected: "test" padded to 33 bytes + "hello"
        let mut expected_hash = Sha256::default();
        let mut padded_prefix = [0u8; 33];
        padded_prefix[..4].copy_from_slice(b"test");
        expected_hash.update(&padded_prefix);
        expected_hash.update(b"hello");

        let mut actual_hash = Sha256::default();
        msg.hash_into(&mut actual_hash);

        assert_eq!(expected_hash.finalize(), actual_hash.finalize());

        // Test length calculation
        assert_eq!(msg.len(), 33 + 5); // 33-byte prefix + 5-byte message
    }

    #[test]
    fn message_new_fixed_key_signature() {
        use crate::{fun::s, new_with_deterministic_nonces};
        use core::str::FromStr;

        // Fixed test to ensure Message::new domain separation doesn't accidentally change
        let schnorr = new_with_deterministic_nonces::<Sha256>();
        let secret_key = s!(42);
        let keypair = schnorr.new_keypair(secret_key);

        let message = Message::<Public>::new("test-app", b"test message");
        let signature = schnorr.sign(&keypair, message);

        // This signature was generated with the current implementation and should never change
        // to ensure backwards compatibility
        let expected_sig = crate::Signature::<Public>::from_str(
            "5c49762df465f21993af631caedb3e478793142e15f200e70511e5af71387e52a3b9b6af189fa4b28a767254f2a8977f2e9db1866ad4dfbb083bb4fbd8dfe82e"
        ).unwrap();

        assert_eq!(
            signature, expected_sig,
            "Message::new signature changed! This breaks backwards compatibility."
        );
    }
}
