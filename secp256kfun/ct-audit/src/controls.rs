use crate::S;
use core::hint;

#[unsafe(no_mangle)]
#[inline(never)]
pub fn ct_control_branch(value: &S) -> u8 {
    let result = crate::audit_scalar_add(value, &S::zero());
    if hint::black_box(result.to_bytes()[31]) == 0 {
        hint::black_box(17)
    } else {
        hint::black_box(29)
    }
}

#[unsafe(no_mangle)]
#[inline(never)]
pub fn ct_control_address(value: &S, table: &[u8; 256]) -> u8 {
    let result = crate::audit_scalar_add(value, &S::zero());
    table[result.to_bytes()[31] as usize]
}
