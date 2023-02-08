use crate::{hash::HashInto, marker::*};
use core::marker::PhantomData;
use subtle::ConstantTimeEq;

/// Potentially secret bytes of arbitrary length.
///
/// This type exists so you can mark some bytes with a [`Secrecy`]. The only
/// automatic effect this has is that equality comparison runs in constant time
/// if either `Slice` is marked [`Secret`].
///
/// [`Secrecy`]: crate::marker::Secrecy
/// [`Secret`]: crate::marker::Secret
///
/// # Example
///
/// ```
/// use secp256kfun::{marker::*, Slice};
/// let bytes = b"a secret message";
/// let secret_slice = Slice::<Secret>::from(bytes.as_ref());
/// ```
#[derive(Debug)]
pub struct Slice<'a, S = Public> {
    pub(crate) inner: &'a [u8],
    secrecy: PhantomData<S>,
}

impl<'a, S> Clone for Slice<'a, S> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner,
            secrecy: PhantomData,
        }
    }
}

impl<'a, S> Copy for Slice<'a, S> {}

impl<'a, 'b, S1, S2> PartialEq<Slice<'b, S2>> for Slice<'a, S1> {
    fn eq(&self, rhs: &Slice<'b, S2>) -> bool {
        // by default do comparison constant time
        self.inner.ct_eq(rhs.inner).into()
    }
}

impl<'a, S> Slice<'a, S> {
    pub(crate) fn from_inner(slice: &'a [u8]) -> Self {
        Self {
            inner: slice,
            secrecy: PhantomData::<S>,
        }
    }

    /// Gets the inner slice
    pub fn as_inner(self) -> &'a [u8] {
        self.inner
    }

    /// Set the secrecy of the bytes to *public*.
    pub fn public(self) -> Slice<'a, Public> {
        Slice::from_inner(self.inner)
    }

    /// Set the secrecy of the bytes to *secret*.
    pub fn secret(self) -> Slice<'a, Secret> {
        Slice::from_inner(self.inner)
    }
}

impl<'a, S> From<Slice<'a, S>> for &'a [u8] {
    fn from(msg: Slice<'a, S>) -> Self {
        msg.inner
    }
}

impl<'a, S> From<&'a [u8]> for Slice<'a, S> {
    fn from(bytes: &'a [u8]) -> Self {
        Self::from_inner(bytes)
    }
}

impl<'a, S> HashInto for Slice<'a, S> {
    fn hash_into(self, hash: &mut impl digest::Digest) {
        hash.update(self.inner)
    }
}

impl<S> core::fmt::Display for Slice<'_, S> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        for byte in self.inner.iter() {
            write!(f, "{byte:02x}")?
        }
        Ok(())
    }
}
