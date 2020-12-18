pub use secp256kfun_parity_backend::scalar::Scalar;
use secp256kfun_parity_backend::{
    ecmult::{ECMultContext, ECMultGenContext},
    field::Field,
    group::{Affine, Jacobian, JACOBIAN_INFINITY},
};
mod constant_time;
mod variable_time;
pub use constant_time::ConstantTime;
pub use variable_time::VariableTime;

pub type Point = Jacobian;

/// A `BasePoint` represents a group element which has pre-computed arithmetic
/// tables to speed up multiplication.
#[derive(Clone, Copy)]
pub struct BasePoint {
    pub(crate) mult_ctx: &'static ECMultContext,
    pub(crate) mult_gen_ctx: &'static ECMultGenContext,
}

impl crate::backend::BackendScalar for Scalar {
    fn minus_one() -> Self {
        Self([
            0xD0364140, 0xBFD25E8C, 0xAF48A03B, 0xBAAEDCE6, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF,
            0xFFFFFFFF,
        ])
    }

    fn from_u32(int: u32) -> Self {
        Self::from_int(int)
    }

    fn zero() -> Self {
        Self::from_int(0)
    }

    fn from_bytes_mod_order(bytes: [u8; 32]) -> Self {
        let mut scalar = Self::default();
        let _ = scalar.set_b32(&bytes);
        scalar
    }

    fn from_bytes(bytes: [u8; 32]) -> Option<Self> {
        let mut scalar = Self::default();
        let overflowed = scalar.set_b32(&bytes);
        if overflowed.into() {
            None
        } else {
            Some(scalar)
        }
    }

    fn to_bytes(&self) -> [u8; 32] {
        self.b32()
    }
}

impl crate::backend::BackendPoint for Jacobian {
    fn zero() -> Jacobian {
        JACOBIAN_INFINITY.clone()
    }

    fn is_zero(&self) -> bool {
        self.is_infinity()
    }

    fn norm_to_xonly(&self) -> XOnly {
        XOnly(self.x.b32())
    }

    fn norm_to_coordinates(&self) -> ([u8; 32], [u8; 32]) {
        crate::assert_normal!(&self);
        (self.x.b32(), self.y.b32())
    }

    fn norm_from_coordinates(x_bytes: [u8; 32], y_bytes: [u8; 32]) -> Option<Jacobian> {
        let mut x = Field::default();
        let mut y = Field::default();
        if !x.set_b32(&x_bytes) {
            return None;
        }

        if !y.set_b32(&y_bytes) {
            return None;
        }

        let mut point = Affine::default();
        point.set_xy(&x, &y);
        if point.is_valid_var() {
            Some(Jacobian::from_ge(&point))
        } else {
            None
        }
    }

    fn norm_from_bytes_y_oddness(x_bytes: [u8; 32], y_odd: bool) -> Option<Jacobian> {
        /// set odd or even in constant time
        // we don't use the one from the inner library because it's vartime
        // and making two versions is too much of a burden atm.
        fn set_xo(point: &mut Affine, x: &Field, y_odd: bool) -> bool {
            if !point.set_xquad(x) {
                return false;
            }
            point.y.normalize();
            let mut neg_y = point.y.neg(1);
            neg_y.normalize();
            point.y.cmov(&neg_y, point.y.is_odd() != y_odd);
            true
        }

        let mut elem = Field::default();
        let mut affine = Affine::default();

        if elem.set_b32(&x_bytes) && set_xo(&mut affine, &elem, y_odd) {
            Some(Jacobian {
                x: affine.x,
                y: affine.y,
                z: Field::from_int(1),
                infinity: false,
            })
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, PartialEq, Copy, Eq, Hash)]
pub struct XOnly([u8; 32]);

impl XOnly {
    fn to_field_elem(&self) -> Field {
        let mut field = Field::default();
        let _success = field.set_b32(&self.0);
        debug_assert!(_success);
        field
    }
}

impl crate::backend::BackendXOnly for XOnly {
    fn from_bytes(bytes: [u8; 32]) -> Option<Self> {
        let mut elem = Field::default();
        let mut affine_coords = Affine::default();
        if elem.set_b32(&bytes) && affine_coords.set_xquad(&elem) {
            Some(Self(bytes))
        } else {
            None
        }
    }

    fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    fn into_bytes(self) -> [u8; 32] {
        self.0
    }

    fn into_norm_point_even_y(self) -> Jacobian {
        let elem = self.to_field_elem();
        let mut affine = Affine::default();
        affine.set_xo_var(&elem, false);
        affine.y.normalize_var();
        Jacobian {
            x: affine.x,
            y: affine.y,
            z: Field::from_int(1),
            infinity: false,
        }
    }
}

static MULT_CTX: ECMultContext =
    unsafe { ECMultContext::new_from_raw(include!(concat!(env!("OUT_DIR"), "/ecmult_table.rs"))) };
static MULT_GEN_CTX: ECMultGenContext = unsafe {
    ECMultGenContext::new_from_raw(include!(concat!(env!("OUT_DIR"), "/ecmult_gen_table.rs")))
};

pub static G_TABLE: BasePoint = BasePoint {
    mult_ctx: &MULT_CTX,
    mult_gen_ctx: &MULT_GEN_CTX,
};

pub const G_JACOBIAN: Jacobian = Jacobian::new(
    Field::new(
        0x79BE667E, 0xF9DCBBAC, 0x55A06295, 0xCE870B07, 0x029BFCDB, 0x2DCE28D9, 0x59F2815B,
        0x16F81798,
    ),
    Field::new(
        0x483ADA77, 0x26A3C465, 0x5DA4FBFC, 0x0E1108A8, 0xFD17B448, 0xA6855419, 0x9C47D08F,
        0xFB10D4B8,
    ),
);

#[macro_export]
#[doc(hidden)]
macro_rules! assert_normal {
    ($point:expr) => {
        debug_assert!({
            let point = $point;
            //HACK: is_odd asserts the field eleem is fully normalized
            let _ = point.x.is_odd();
            let _ = point.y.is_odd();
            point.is_infinity() || point.z == Field::from_int(1)
        })
    };
}
