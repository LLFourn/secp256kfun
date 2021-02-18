/// Utility tarait for something that can be written as a string.
///
/// This is basically like [`core::fmt::Display`] except the thing being written to does not have to
/// be a `Formatter`. This is useful because we write the names of [`Sigma`] protocols to a hash
/// input but also use `Writable` implementation to implement [`core::fmt::Display`].
///
/// [`Sigma`]: crate::Sigma
pub trait Writable {
    /// Asks the thing to write itself to `W`.
    fn write_to<W: core::fmt::Write>(&self, w: &mut W) -> core::fmt::Result;
}

impl Writable for str {
    fn write_to<W: core::fmt::Write>(&self, w: &mut W) -> core::fmt::Result {
        write!(w, "{}", self)
    }
}
