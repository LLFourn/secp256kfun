/// A marker trait implemented by [`Secret`] and [`Public`].
///
/// [`Scalar`s] and [`Point`s] both have a `Secrecy` type parameter which must
/// be either [`Secret`] or [`Public`]. At a high level these indicate:
///
/// - [`Secret`]: This value must be kept secret from parties I interact with.
/// - [`Public`]: This value is known or it would not harm my security if this
///   value is known to all parties I interact with.
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
/// use secp256kfun::{G, Point, Scalar, g, marker::*};
/// let x = Scalar::random(&mut rand::thread_rng());
/// let H = Point::random(&mut rand::thread_rng());
/// let X = g!(x * H); // Secret requires the constant-time implementation.
/// let x = x.public();
/// let X = g!(x * H); // Public permits variable-time algorithms.
/// ```
///
/// Markers do not enable CPU timing protections or verify compiler output.
/// See the [timing and platform requirements](crate#timing-and-platform-requirements),
/// including the caller's responsibility for Apple timing-safe execution context.
///
/// [`Secret`]: crate::marker::Secret
/// [`Point`]: crate::marker::Public
/// [`Scalar`s]: crate::Scalar
/// [`Point`s]: crate::Point
pub trait Secrecy: Default + Clone + PartialEq + Eq + Copy + 'static + Ord + PartialOrd {}

/// Requires core operations to use implementations obligated to keep control flow
/// and memory addresses independent of this value, under their valid-input contracts.
///
/// This marker does not enable CPU protections or guarantee hardware timing safety.
/// The [timing and platform requirements](crate#timing-and-platform-requirements)
/// apply to callers, including those using Apple silicon.
#[derive(Debug, Clone, Default, PartialEq, Eq, Copy, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "bincode", derive(bincode::Encode, bincode::Decode))]
pub struct Secret;

/// Indicates that variable time operations may be used on the value.
#[derive(Debug, Clone, Default, PartialEq, Eq, Copy, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "bincode", derive(bincode::Encode, bincode::Decode))]
pub struct Public;

impl Secrecy for Secret {}

impl Secrecy for Public {}
