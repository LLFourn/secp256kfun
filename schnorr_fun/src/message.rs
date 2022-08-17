use secp256kfun::{digest::Digest, hash::HashInto, marker::*, Slice};

/// A message to be signed.
///
/// The `S` parameter is a [`Secrecy`] which is used when signing a verifying to check whether the
/// challenge scalar produced with the message should be secret.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Message<'a, S = Public> {
    /// The message bytes
    pub bytes: Slice<'a, S>,
    /// The optional application tag to separate the signature from other applications.
    pub app_tag: Option<&'static str>,
}

impl<'a, 'b, S: Secrecy> Message<'a, S> {
    /// Create a raw message with no `app_tag`. The message bytes will be passed straight into the
    /// challenge hash. Usually, you only use this when signing a pre-hashed message.
    pub fn raw(bytes: &'a [u8]) -> Self {
        Message {
            bytes: bytes.mark::<S>(),
            app_tag: None,
        }
    }

    /// Signs a plain variable length message.
    ///
    /// You must provide an application tag to make sure signatures valid in one context are not
    /// valid in another. The tag is used as described [here].
    ///
    /// [here]: https://github.com/sipa/bips/issues/207#issuecomment-673681901
    pub fn plain(app_tag: &'static str, bytes: &'a [u8]) -> Self {
        assert!(app_tag.len() <= 64, "tag must be 64 bytes or less");
        assert!(!app_tag.is_empty(), "tag must not be empty");
        Message {
            bytes: bytes.mark::<S>(),
            app_tag: Some(app_tag),
        }
    }

    /// Length of the message as it is hashed
    pub fn len(&self) -> usize {
        match self.app_tag {
            Some(_) => 64 + self.bytes.as_inner().len(),
            None => self.bytes.as_inner().len(),
        }
    }
}

impl<S> HashInto for Message<'_, S> {
    fn hash_into(self, hash: &mut impl Digest) {
        if let Some(prefix) = self.app_tag {
            let mut padded_prefix = [0u8; 64];
            padded_prefix[..prefix.len()].copy_from_slice(prefix.as_bytes());
            hash.update(padded_prefix);
        }
        hash.update(<&[u8]>::from(self.bytes));
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use sha2::Sha256;

    #[test]
    fn message_hash_into() {
        let mut hash1 = Sha256::default();
        hash1.update("test");
        hash1.update([0u8; 60].as_ref());
        hash1.update("hello world");

        let mut hash2 = Sha256::default();
        Message::<Public>::plain("test", b"hello world").hash_into(&mut hash2);

        assert_eq!(hash1.finalize(), hash2.finalize());
    }
}
