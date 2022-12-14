/// A marker trait implemented by [`Secret`] and [`Public`].
///
/// [`Scalar`s] and [`Point`s] both have a `Secrecy` type parameter which must
/// be either [`Secret`] or [`Public`]. At a high level these indicate:
///
/// - [`Secret`]: This value must be kept secret from parties I interact with.
/// - [`Public`]: This value is known or it would not harm my security if this
///               value is known to all parties I interact with.
///
/// Note this consideration is only important if you do operations on the value
/// during an interaction with a party. So if you would like to keep scalar `x`
/// secret from party C but you only do operations on `x` while interacting with
/// `B` (who perhaps, already knows it), then, in theory, `x` can be marked
/// `Public`.  However it is up to you to make sure these conditions hold so the
/// prudent thing to do is make sure that anything that might be secret in some
/// circumstance is marked [`Secret`].
///
/// [`Scalar`s] are by default [`Secret`] and [`Point`s] are by default [`Public`]. The `.secret()`
/// and `.public()` methods allow you to change the default.
///
/// ```
/// use secp256kfun::{g, marker::*, Point, Scalar, G};
/// let x = Scalar::random(&mut rand::thread_rng());
/// let H = Point::random(&mut rand::thread_rng());
/// let X = g!(x * H); // This is constant time because x is secret by default.
/// let x = x.public();
/// let X = g!(x * H); // This may run faster (in variable time)
/// ```
///
/// [`Secret`]: crate::marker::Secret
/// [`Point`]: crate::marker::Public
/// [`Scalar`s]: crate::Scalar
/// [`Point`s]: crate::Point
pub trait Secrecy: Default + Clone + PartialEq + Eq + Copy + 'static + Ord + PartialOrd {}

/// Indicates that the value is secret and therefore makes core operations
/// executed on it to use  _constant time_ versions of the operations.
#[derive(Debug, Clone, Default, PartialEq, Eq, Copy, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct Secret;

/// Indicates that variable time operations may be used on the value.
#[derive(Debug, Clone, Default, PartialEq, Eq, Copy, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct Public;

impl Secrecy for Secret {}

impl Secrecy for Public {}
