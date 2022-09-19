//! Helper functions.
/// Computes `a + b + carry`, returning the result along with the new carry. 32-bit version.
#[inline(always)]
#[cfg(target_pointer_width = "32")]
pub const fn adc32(a: u32, b: u32, carry: u32) -> (u32, u32) {
    let ret = (a as u64) + (b as u64) + (carry as u64);
    (ret as u32, (ret >> 32) as u32)
}

/// Computes `a + b + carry`, returning the result along with the new carry. 64-bit version.
#[cfg(target_pointer_width = "64")]
#[inline(always)]
pub const fn adc64(a: u64, b: u64, carry: u64) -> (u64, u64) {
    let ret = (a as u128) + (b as u128) + (carry as u128);
    (ret as u64, (ret >> 64) as u64)
}

/// Computes `a - (b + borrow)`, returning the result along with the new borrow. 32-bit version.
#[inline(always)]
#[cfg(target_pointer_width = "32")]
pub const fn sbb32(a: u32, b: u32, borrow: u32) -> (u32, u32) {
    let ret = (a as u64).wrapping_sub((b as u64) + ((borrow >> 31) as u64));
    (ret as u32, (ret >> 32) as u32)
}

/// Computes `a - (b + borrow)`, returning the result along with the new borrow. 64-bit version.
#[cfg(target_pointer_width = "64")]
#[inline(always)]
pub const fn sbb64(a: u64, b: u64, borrow: u64) -> (u64, u64) {
    let ret = (a as u128).wrapping_sub((b as u128) + ((borrow >> 63) as u128));
    (ret as u64, (ret >> 64) as u64)
}
