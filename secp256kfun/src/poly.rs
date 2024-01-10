//! Utilities for working with polynomials on the secp256k1 elliptic curve.
//!
//! A polynomial f(x) of degree k is defined by its coefficients
//!
//! `f(x) = a_0 + a_1 * x + a_2 * x^2 + ... + a_k * x^k`
use core::iter;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use rand_core::RngCore;

use crate::{
    g,
    marker::{NonNormal, PointType, Public, Secrecy, Secret, Zero, ZeroChoice},
    s, Point, Scalar, G,
};

/// Create a vector of points by multiplying each scalar by `G`.
///
/// # Example
///
/// ```
/// use schnorr_fun::{
///     frost,
///     fun::{g, s, Scalar, G},
/// };
/// let secret_poly = (0..5)
///     .map(|_| Scalar::random(&mut rand::thread_rng()))
///     .collect::<Vec<_>>();
/// let point_poly = frost::to_point_poly(&secret_poly);
/// ```
pub fn to_point_poly(scalar_poly: &[Scalar]) -> Vec<Point> {
    scalar_poly.iter().map(|a| g!(a * G).normalize()).collect()
}

/// Generate a [`Scalar`] polynomial for key generation
///
/// [`Scalar`]: secp256kfun::Scalar
pub fn generate_scalar_poly(threshold: usize, rng: &mut impl RngCore) -> Vec<Scalar> {
    (0..threshold).map(|_| Scalar::random(rng)).collect()
}

/// Evaluate a scalar polynomial defined by coefficients, at some scalar index.
///
/// The polynomial coefficients begin with the smallest degree term first (the constant).
pub fn scalar_poly_eval(
    poly: &[Scalar],
    x: Scalar<impl Secrecy, impl ZeroChoice>,
) -> Scalar<Secret, Zero> {
    s!(powers(x) .* poly)
}

/// Evaluate a point polynomial defined by coefficients, at some index.
///
/// The polynomial coefficients begin with the smallest degree term first (the constant).
pub fn point_poly_eval(
    poly: &[Point<impl PointType, Public, impl ZeroChoice>],
    x: Scalar<Public, impl ZeroChoice>,
) -> Point<NonNormal, Public, Zero> {
    g!(powers(x) .* poly)
}

/// Returns an iterator of 1, x, x², x³ ...
fn powers<S: Secrecy, Z: ZeroChoice>(x: Scalar<S, Z>) -> impl Iterator<Item = Scalar<S, Z>> {
    core::iter::successors(Some(Scalar::one().mark_zero_choice::<Z>()), move |xpow| {
        Some(s!(xpow * x).set_secrecy())
    })
}

/// Calculate the lagrange coefficient for participant with index x_j and other signers indexes x_ms
pub fn lagrange_lambda(
    x_j: Scalar<impl Secrecy>,
    x_ms: impl Iterator<Item = Scalar<impl Secrecy>>,
) -> Scalar<Public> {
    x_ms.fold(Scalar::one(), |acc, x_m| {
        let denominator = s!(x_m - x_j)
            .non_zero()
            .expect("indexes must be unique")
            .invert();
        s!(acc * x_m * denominator).public()
    })
}

/// Find the coefficients of the polynomial that interpolates a set of points at unique indexes.
///
/// Panics if the indexes are not unique.
///
/// A vector with a tail of zero coefficients means the interpolation was overdetermined.
pub fn interpolate_point_polynomial(
    points_at_indexes: Vec<(Scalar<impl Secrecy, impl ZeroChoice>, Point)>,
) -> Vec<Point<impl PointType, Public, Zero>> {
    let (indexes, points): (Vec<_>, Vec<_>) = points_at_indexes.into_iter().unzip();
    // Get each lagrange basis polynomial from the product of coefficients:
    //      l_j(x) = Product[ (x-x_m)/(x_j-x_m), j!=m]
    // Or
    //      l_j(x) = Product[ a_m*x + b_m, j!=m], where a_m = 1/(x_j-x_m) and b_m = -x_m*a_m.
    let basis_polynomials: Vec<_> = indexes
        .clone()
        .into_iter()
        .enumerate()
        .map(|(j, x_j)| {
            let mut coefficients: Vec<_> = vec![];
            for (_, x_m) in indexes.iter().enumerate().filter(|(m, _)| *m != j) {
                let a_m = s!(x_j - x_m)
                    .non_zero()
                    .expect("points must lie at unique indexes to interpolate")
                    .invert();
                let b_m = s!(-x_m * a_m).mark_zero();

                // Multiply out the product. Beginning with the first two coefficients
                // we then take the next set (b_1, a_1), multiply through, and collect terms.
                if coefficients.is_empty() {
                    coefficients.extend([b_m.mark_zero(), a_m.mark_zero()])
                } else {
                    let mut updated_coefficients = coefficients.clone();
                    for i in 0..coefficients.len() {
                        let bumping_up_degree = if i != 0 {
                            s!({ &coefficients[i - 1] } * a_m)
                        } else {
                            s!(0)
                        };
                        let same_degree = s!({ &coefficients[i] } * b_m);
                        updated_coefficients[i] = s!(same_degree + bumping_up_degree);
                    }
                    let higher_degree = s!({ coefficients.last().unwrap() } * a_m);
                    updated_coefficients.push(higher_degree);
                    coefficients = updated_coefficients;
                }
            }
            coefficients
        })
        .collect();

    let interpolating_basis: Vec<_> = basis_polynomials
        .iter()
        .zip(points)
        .map(|(basis_poly, y_value)| point_mul(basis_poly, &y_value))
        .collect();

    let point_polynomial = interpolating_basis.into_iter().fold(
        Vec::with_capacity(basis_polynomials[0].len()),
        |acc, poly| add(&acc, &poly),
    );

    point_polynomial
}

/// Multiply a scalar polynomial by a point
pub fn point_mul(
    poly: &Vec<Scalar<impl Secrecy, impl ZeroChoice>>,
    point: &Point,
) -> Vec<Point<NonNormal, Public, Zero>> {
    poly.iter()
        .map(|coeff| g!(coeff * point).mark_zero())
        .collect::<Vec<_>>()
}

/// Add two point polynomials
pub fn add<T: PointType + Default, S: Secrecy>(
    poly1: &[Point<T, S, Zero>],
    poly2: &[Point<T, S, Zero>],
) -> Vec<Point<NonNormal, Public, Zero>> {
    let (long, short) = if poly1.len() >= poly2.len() {
        (poly1, poly2)
    } else {
        (poly2, poly1)
    };

    long.into_iter()
        .zip(short.into_iter().chain(iter::repeat(&Point::zero())))
        .map(|(c1, c2)| g!(c1 + c2))
        .collect()
}

/// Interpolate a set of shamir secret shares to find the joint secret
///
/// Panics if the indexes are not unique.
pub fn reconstruct_shared_secret(
    indexes: Vec<Scalar>,
    secrets: Vec<Scalar<impl Secrecy, impl ZeroChoice>>,
) -> Scalar {
    let coefficients: Vec<_> = indexes
        .iter()
        .map(|my_index| {
            lagrange_lambda(
                my_index.clone(),
                indexes.clone().into_iter().filter(|j| j != my_index),
            )
        })
        .collect();
    secrets
        .into_iter()
        .zip(coefficients)
        .fold(s!(0).mark_zero(), |acc, (secret, coefficient)| {
            s!(acc + secret * coefficient)
        })
        .non_zero()
        .expect("joint secret should not be zero")
}

#[cfg(test)]
mod test {
    use crate::marker::Normal;

    use super::*;

    #[test]
    fn test_lagrange_lambda() {
        let res = s!((1 * 4 * 5) * {
            s!((1 - 2) * (4 - 2) * (5 - 2))
                .non_zero()
                .expect("")
                .invert()
        });
        assert_eq!(
            res,
            lagrange_lambda(s!(2), [s!(1), s!(4), s!(5)].into_iter())
        );
    }

    #[test]
    fn test_recover_public_poly() {
        let poly = vec![g!(1 * G), g!(2 * G), g!(3 * G)];
        let indexes = vec![s!(1), s!(3), s!(2)];
        let points = indexes
            .clone()
            .into_iter()
            .map(|index| {
                (
                    index.clone(),
                    point_poly_eval(&poly, index.public())
                        .normalize()
                        .non_zero()
                        .unwrap(),
                )
            })
            .collect::<Vec<_>>();

        let interpolation = interpolate_point_polynomial(points);
        assert_eq!(interpolation, poly)
    }

    #[test]
    fn test_recover_overdetermined_poly() {
        let poly = vec![g!(1 * G), g!(2 * G), g!(3 * G)];
        let indexes = vec![s!(1), s!(2), s!(3), s!(4), s!(5)];
        let points = indexes
            .clone()
            .into_iter()
            .map(|index| {
                (
                    index.clone(),
                    point_poly_eval(&poly, index.public())
                        .normalize()
                        .non_zero()
                        .unwrap(),
                )
            })
            .collect::<Vec<_>>();

        let interpolation = interpolate_point_polynomial(points);

        let (interpolated_coeffs, zero_coeffs) = interpolation.split_at(poly.len());
        let n_extra_points = indexes.len() - poly.len();
        assert_eq!(
            (0..n_extra_points)
                .into_iter()
                .map(|_| Point::<Normal, Public, Zero>::zero().public().normalize())
                .collect::<Vec<_>>(),
            zero_coeffs.to_vec()
        );
        assert_eq!(interpolated_coeffs, poly);
    }

    #[test]
    fn test_reconstruct_shared_secret() {
        let scalar_poly = vec![s!(42), s!(53), s!(64)];
        let indexes = vec![s!(1), s!(2), s!(3)];

        let secret_shares: Vec<_> = indexes
            .clone()
            .into_iter()
            .map(|index| scalar_poly_eval(&scalar_poly, index))
            .collect();

        let reconstructed_secret = reconstruct_shared_secret(indexes, secret_shares);
        assert_eq!(scalar_poly[0], reconstructed_secret);
    }
}
