//! Utilities for working with polynomials on the secp256k1 elliptic curve.
//!
//! A polynomial defined by its coefficients a_0, ... a_k. The coefficients can be [`Scalars`] or [`Points`].
//!
//! `f(x) = a_0 + a_1 * x + a_2 * x^2 + ... + a_k * x^k`
//!
//! [`Scalars`]: crate::Scalar
//! [`Points`]: crate::Point
use crate::{g, marker::*, s, Point, Scalar, G};
use alloc::vec::Vec;
use rand_core::RngCore;

/// Functions for dealing with scalar polynomials
pub mod scalar {
    use super::*;

    /// Evaluate a scalar polynomial defined by coefficients, at some scalar index.
    ///
    /// The polynomial coefficients begin with the smallest degree term first (the constant).
    pub fn eval(
        poly: &[Scalar<impl Secrecy, impl ZeroChoice>],
        x: Scalar<impl Secrecy, impl ZeroChoice>,
    ) -> Scalar<Secret, Zero> {
        s!(powers(x) .* poly)
    }

    /// Create a vector of points by multiplying each scalar by `G`.
    ///
    /// # Example
    ///
    /// ```
    /// use secp256kfun::{poly, Scalar};
    /// let secret_poly = (0..5)
    ///     .map(|_| Scalar::random(&mut rand::thread_rng()))
    ///     .collect::<Vec<_>>();
    /// let point_poly = poly::scalar::to_point_poly(&secret_poly);
    /// ```
    pub fn to_point_poly(scalar_poly: &[Scalar]) -> Vec<Point> {
        scalar_poly.iter().map(|a| g!(a * G).normalize()).collect()
    }

    /// Generate a [`Scalar`] polynomial for key generation
    ///
    /// [`Scalar`]: crate::Scalar
    pub fn generate(threshold: usize, rng: &mut impl RngCore) -> Vec<Scalar> {
        (0..threshold).map(|_| Scalar::random(rng)).collect()
    }

    /// Evalulate the polynomial that passes through the points in `x_and_y` at `0`.
    ///
    /// This is useful for recovering a secret from a set of Sharmir Secret Shares. Each shamir
    /// secret share is associated with a participant index (index, share).
    pub fn interpolate_and_eval_poly_at_0(
        x_and_y: &[(Scalar<Public>, Scalar<impl Secrecy, impl ZeroChoice>)],
    ) -> Scalar<Secret, Zero> {
        let indices = x_and_y.iter().map(|(index, _)| *index);
        x_and_y
            .iter()
            .map(|(index, secret)| {
                let lambda = eval_basis_poly_at_0(*index, indices.clone());
                s!(secret * lambda)
            })
            .fold(s!(0), |interpolated_poly, scaled_basis_poly| {
                s!(interpolated_poly + scaled_basis_poly)
            })
    }

    /// Interpolate a polynomial that runs through a list of `(x, y)` coordinate points represented
    /// as scalars. In most protocols the `x` is usually known to everyone in the protocol while the
    /// `y` is the party's signing key.
    pub fn interpolate<S: Secrecy>(
        x_and_y: &[(Scalar<Public>, Scalar<S, impl ZeroChoice>)],
    ) -> Vec<Scalar<S, Zero>> {
        let x_ms = x_and_y.iter().map(|(index, _)| *index);
        let mut interpolating_polynomial: Vec<Scalar<S, Zero>> = vec![];
        for (x_j, y_j) in x_and_y {
            let basis_poly = super::lagrange_basis_poly(*x_j, x_ms.clone());
            let scaled_basis_poly = basis_poly
                .iter()
                .map(|coeff| s!(coeff * y_j))
                .collect::<Vec<_>>();
            self::add_in_place(&mut interpolating_polynomial, scaled_basis_poly);
        }

        interpolating_polynomial
    }

    /// Multiplies two polynomials of the same [`Secrecy`].
    ///
    /// The secrecy of the result will be the [`Secrecy`] of the inputs.
    pub fn mul<S: Secrecy>(
        a: &[Scalar<S, impl ZeroChoice>],
        b: &[Scalar<S, impl ZeroChoice>],
    ) -> Vec<Scalar<S, Zero>> {
        let mut result = vec![Scalar::zero(); a.len() + b.len() - 1];
        for (i, &coeff_a) in a.iter().enumerate() {
            for (j, &coeff_b) in b.iter().enumerate() {
                result[i + j] = s!(result[i + j] + coeff_a.mark_zero() * coeff_b.mark_zero())
                    .set_secrecy::<S>();
            }
        }

        result
    }

    /// Adds two scalar polynomials together where `apoly` is mutated to form the result.
    pub fn add_in_place<SA: Secrecy>(
        apoly: &mut Vec<Scalar<SA, Zero>>,
        bpoly: impl IntoIterator<Item = Scalar<impl Secrecy, impl ZeroChoice>>,
    ) {
        let b = bpoly.into_iter();
        for (i, b) in b.enumerate() {
            if i == apoly.len() {
                apoly.push(b.set_secrecy::<SA>().mark_zero());
            } else {
                apoly[i] += b;
            }
        }
    }

    /// Adds two scalar polynomials.
    pub fn add(
        apoly: impl IntoIterator<Item = Scalar<impl Secrecy, impl ZeroChoice>>,
        bpoly: impl IntoIterator<Item = Scalar<impl Secrecy, impl ZeroChoice>>,
    ) -> impl Iterator<Item = Scalar<Secret, Zero>> {
        let mut a = apoly.into_iter();
        let mut b = bpoly.into_iter();

        core::iter::from_fn(move || match (a.next(), b.next()) {
            (Some(a), Some(b)) => Some(s!(a + b)),
            (Some(a), None) => Some(a.mark_zero().secret()),
            (None, Some(b)) => Some(b.mark_zero().secret()),
            _ => None,
        })
    }

    /// Negates a scalar polynomial
    pub fn negate(poly: &mut [Scalar<impl Secrecy, impl ZeroChoice>]) {
        for coeff in poly {
            *coeff = -*coeff;
        }
    }
}

/// Functions for dealing with point polynomials
pub mod point {
    use super::*;

    /// Evaluate a point polynomial defined by coefficients, at some index.
    ///
    /// The polynomial coefficients begin with the smallest degree term first (the constant).
    pub fn eval<T: PointType>(
        poly: &[Point<T, Public, impl ZeroChoice>],
        x: Scalar<Public, impl ZeroChoice>,
    ) -> Point<NonNormal, Public, Zero> {
        g!(powers(x) .* poly)
    }

    /// Adds two point polynomials together where `apoly` is mutated to form the result.
    pub fn add_in_place<SA: Secrecy>(
        apoly: &mut Vec<Point<NonNormal, SA, Zero>>,
        bpoly: impl IntoIterator<Item = Point<impl PointType, impl Secrecy, impl ZeroChoice>>,
    ) {
        let b = bpoly.into_iter();
        for (i, b) in b.enumerate() {
            if i == apoly.len() {
                apoly.push(b.set_secrecy::<SA>().mark_zero().non_normal());
            } else {
                apoly[i] += b;
            }
        }
    }

    /// Adds two point polynomails.
    pub fn add(
        poly1: impl IntoIterator<Item = Point<impl PointType, impl Secrecy, impl ZeroChoice>>,
        poly2: impl IntoIterator<Item = Point<impl PointType, impl Secrecy, impl ZeroChoice>>,
    ) -> impl Iterator<Item = Point<NonNormal, Public, Zero>> {
        let mut poly1 = poly1.into_iter();
        let mut poly2 = poly2.into_iter();

        core::iter::from_fn(move || match (poly1.next(), poly2.next()) {
            (Some(a), Some(b)) => Some(g!(a + b)),
            (Some(a), None) => Some(a.mark_zero().public().non_normal()),
            (None, Some(b)) => Some(b.mark_zero().public().non_normal()),
            _ => None,
        })
    }

    /// Find the coefficients of the polynomial that interpolates a set of points (index, point).
    ///
    /// Panics if the indices are not unique.
    ///
    /// A vector with a tail of zero coefficients means the interpolation was overdetermined.
    #[allow(clippy::type_complexity)]
    pub fn interpolate(
        index_and_point: &[(
            Scalar<Public, impl ZeroChoice>,
            Point<impl PointType, impl Secrecy, impl ZeroChoice>,
        )],
    ) -> Vec<Point<NonNormal, Public, Zero>> {
        let x_ms = index_and_point.iter().map(|(index, _)| *index);
        let mut interpolating_polynomial: Vec<Point<NonNormal, Public, Zero>> = vec![];
        for (x_j, y_j) in index_and_point {
            let basis_poly = super::lagrange_basis_poly(*x_j, x_ms.clone());
            let point_scaled_basis_poly = basis_poly
                .iter()
                .map(|coeff| g!(coeff * y_j))
                .collect::<Vec<_>>();
            self::add_in_place(&mut interpolating_polynomial, point_scaled_basis_poly);
        }

        while interpolating_polynomial.len() > 1
            && interpolating_polynomial.last().unwrap().is_zero()
        {
            interpolating_polynomial.pop();
        }

        interpolating_polynomial
    }

    /// Negates a scalar polynomial
    pub fn negate<T>(poly: &mut [Point<T, impl Secrecy, impl ZeroChoice>])
    where
        T: PointType<NegationType = T>,
    {
        for coeff in poly {
            *coeff = -*coeff;
        }
    }

    /// Normalizes the points in a polynomial
    pub fn normalize<S, Z>(
        poly: impl IntoIterator<Item = Point<impl PointType, S, Z>>,
    ) -> impl Iterator<Item = Point<Normal, S, Z>> {
        poly.into_iter().map(|point| point.normalize())
    }
}
/// Returns an iterator of 1, x, x², x³ ...
fn powers<S: Secrecy, Z: ZeroChoice>(x: Scalar<S, Z>) -> impl Iterator<Item = Scalar<S, Z>> {
    core::iter::successors(Some(Scalar::one().mark_zero_choice::<Z>()), move |xpow| {
        Some(s!(xpow * x).set_secrecy())
    })
}

/// Evaluate the lagrange basis polynomial for the x coordinate `x_j` interpolated with the nodes `x_ms` at 0.
///
/// Described as the lagrange coefficient in FROST. Useful when interpolating a sharmir shared
/// secret which usually lies at the value of the polynomial evaluated at 0.
pub fn eval_basis_poly_at_0(
    x_j: Scalar<impl Secrecy>,
    x_ms: impl IntoIterator<Item = Scalar<impl Secrecy>>,
) -> Scalar<Public> {
    // NOTE: we don't compute the whole basis poly to do this because it's faster and simpler to do
    // it this way
    let (num, denom) = x_ms.into_iter().filter(|x_m| *x_m != x_j).fold(
        (Scalar::<Public, _>::one(), Scalar::<Public, _>::one()),
        |(mut numerator, mut denominator), x_m| {
            numerator *= x_m;
            denominator *= s!(x_m - x_j).non_zero().expect("x_m != x_j");
            (numerator, denominator)
        },
    );

    // do the division at the end for efficiency's sake
    s!(num / denom).public()
}

/// Computes the (unscaled) lagrange basis polynomial given the index `x_j` you want the basis poly
/// for and the other x-coordinates in the interpolation `x_ms`. If `x_j` is also in `x_ms` it will
/// be ignored.
pub fn lagrange_basis_poly(
    x_j: Scalar<Public, impl ZeroChoice>,
    x_ms: impl IntoIterator<Item = Scalar<Public, impl ZeroChoice>>,
) -> Vec<Scalar<Public, Zero>> {
    // the identity polynomial
    let mut result = vec![s!(1).public().mark_zero()];
    for x_m in x_ms.into_iter() {
        if x_m == x_j {
            continue;
        }
        // Basis polynomial calculated from the product of these indices coefficients:
        //  l_j(x) = Product[ (x-x_m)/(x_j-x_m), j!=m ]
        //  l_j(x) = Product[ a_m*x + b_m, j!=m], where a_m = 1/(x_j-x_m) and b_m = -x_m*a_m.

        // coefficient of x
        let a_m = s!(x_j - x_m)
            .non_zero()
            .expect("x_m == x_j excluded")
            .invert()
            .mark_zero()
            .public();
        // coefficient of 1
        let b_m = s!(-x_m * a_m).mark_zero().public();

        // we want to figure out (a_m * x + b_m) * result
        result = scalar::mul(&result[..], &[b_m, a_m]);
    }

    result
}
