//! Utilities for working with polynomials on the secp256k1 elliptic curve.
//!
//! A polynomial f(x) of degree k is defined by its coefficients
//!
//! `f(x) = a_0 + a_1 * x + a_2 * x^2 + ... + a_k * x^k`

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crate::{
    marker::{Public, Secrecy, Secret, Zero, ZeroChoice},
    s, Scalar,
};

/// Functions for dealing with scalar polynomials
pub mod scalar {
    #[cfg(feature = "alloc")]
    use alloc::vec::Vec;
    use rand_core::RngCore;

    use crate::{
        g,
        marker::{Secrecy, Secret, Zero, ZeroChoice},
        poly::powers,
        s, Point, Scalar, G,
    };

    /// Evaluate a scalar polynomial defined by coefficients, at some scalar index.
    ///
    /// The polynomial coefficients begin with the smallest degree term first (the constant).
    pub fn eval(poly: &[Scalar], x: Scalar<impl Secrecy, impl ZeroChoice>) -> Scalar<Secret, Zero> {
        s!(powers(x) .* poly)
    }

    /// Create a vector of points by multiplying each scalar by `G`.
    ///
    /// # Example
    ///
    /// ```
    /// use secp256kfun::{g, poly, s, Scalar, G};
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
}

/// Functions for dealing with point polynomials
pub mod point {
    use core::iter;

    #[cfg(feature = "alloc")]
    use alloc::vec::Vec;

    use crate::{
        g,
        marker::{NonNormal, PointType, Public, Secrecy, Zero, ZeroChoice},
        poly::powers,
        s, Point, Scalar,
    };

    /// Evaluate a point polynomial defined by coefficients, at some index.
    ///
    /// The polynomial coefficients begin with the smallest degree term first (the constant).
    pub fn eval<T: PointType>(
        poly: &[Point<T, Public, impl ZeroChoice>],
        x: Scalar<Public, impl ZeroChoice>,
    ) -> Point<NonNormal, Public, Zero> {
        g!(powers(x) .* poly)
    }

    /// Add the coefficients of two point polynomials.
    ///
    /// Handles mismatched polynomial lengths.
    pub fn add<T: PointType + Default, S: Secrecy, Z: ZeroChoice>(
        poly1: &[Point<T, S, Z>],
        poly2: &[Point<T, S, Z>],
    ) -> Vec<Point<NonNormal, Public, Zero>> {
        let (long, short) = if poly1.len() >= poly2.len() {
            (poly1, poly2)
        } else {
            (poly2, poly1)
        };

        long.iter()
            .map(|c| c.mark_zero())
            .zip(
                short
                    .iter()
                    .map(|c| c.mark_zero())
                    .chain(iter::repeat(Point::zero())),
            )
            .map(|(c1, c2)| g!(c1 + c2))
            .collect()
    }

    /// Find the coefficients of the polynomial that interpolates a set of points (index, point).
    ///
    /// Panics if the indicies are not unique.
    ///
    /// A vector with a tail of zero coefficients means the interpolation was overdetermined.
    pub fn interpolate(
        points_at_indicies: Vec<(Scalar<Public, impl ZeroChoice>, Point)>,
    ) -> Vec<Point<impl PointType, Public, Zero>> {
        // let (indicies, points): (Vec<_>, Vec<_>) = points_at_indicies.into_iter().unzip();

        let mut interpolating_polynomial = Vec::with_capacity(points_at_indicies.len());
        for (j, (x_j, y_j)) in points_at_indicies.iter().enumerate() {
            // Basis polynomial calculated from the product of these indices coefficients:
            //      l_j(x) = Product[ (x-x_m)/(x_j-x_m), j!=m ]
            // Or
            //      l_j(x) = Product[ a_m*x + b_m, j!=m], where a_m = 1/(x_j-x_m) and b_m = -x_m*a_m.
            let mut basis_polynomial: Vec<_> = vec![];
            for (_, x_m) in points_at_indicies
                .iter()
                .map(|(x_m, _)| x_m)
                .enumerate()
                .filter(|(m, _)| *m != j)
            {
                let a_m = s!(x_j - x_m)
                    .non_zero()
                    .expect("points must lie at unique indicies to interpolate")
                    .invert();
                let b_m = s!(-x_m * a_m).mark_zero();

                // Multiply out the product. Beginning with the first two coefficients
                // we then take the next set (b_1, a_1), multiply through, and collect terms.
                if basis_polynomial.is_empty() {
                    basis_polynomial.extend([b_m.mark_zero().public(), a_m.mark_zero().public()])
                } else {
                    let mut prev_coeff = s!(0).public();
                    for coeff in basis_polynomial.iter_mut() {
                        let bumping_up_degree = s!(prev_coeff * a_m);
                        prev_coeff = *coeff;

                        let same_degree = s!(prev_coeff * b_m);
                        *coeff = s!(same_degree + bumping_up_degree).public();
                    }
                    let higher_degree = s!(prev_coeff * a_m);
                    basis_polynomial.push(higher_degree.public());
                }
            }

            let point_scaled_basis_polynomial = basis_polynomial
                .iter()
                .map(|coeff| g!(coeff * y_j).mark_zero())
                .collect::<Vec<_>>();

            interpolating_polynomial =
                self::add(&interpolating_polynomial, &point_scaled_basis_polynomial)
        }

        interpolating_polynomial
    }
}
/// Returns an iterator of 1, x, x², x³ ...
fn powers<S: Secrecy, Z: ZeroChoice>(x: Scalar<S, Z>) -> impl Iterator<Item = Scalar<S, Z>> {
    core::iter::successors(Some(Scalar::one().mark_zero_choice::<Z>()), move |xpow| {
        Some(s!(xpow * x).set_secrecy())
    })
}

/// Evaluate the lagrange basis polynomial for the x coordinate x_j interpolated with the nodes x_ms at 0.
///
/// Described as the lagrange coefficient in FROST. Useful when interpolating a sharmir shared
/// secret which usually lies at the value of the polynomial evaluated at 0.
pub fn eval_basis_poly_at_0(
    x_j: Scalar<impl Secrecy>,
    x_ms: impl Iterator<Item = Scalar<impl Secrecy>>,
) -> Scalar<Public> {
    x_ms.fold(Scalar::one(), |acc, x_m| {
        let denominator = s!(x_m - x_j).non_zero().expect("indicies must be unique");
        s!(acc * x_m / denominator).public()
    })
}

/// Interpolate a set of shamir secret shares to find the joint secret.
///
/// Each shamir secret share is associated with a participant index (index, share).
///
/// Panics if the indicies are not unique.
pub fn reconstruct_shared_secret(
    secrets_at_indices: Vec<(Scalar, Scalar<Secret, impl ZeroChoice>)>,
) -> Scalar<Secret, Zero> {
    let (indicies, secrets): (Vec<_>, Vec<_>) = secrets_at_indices.into_iter().unzip();
    indicies
        .iter()
        .zip(secrets)
        .map(|(index, secret)| {
            let lambda =
                eval_basis_poly_at_0(*index, indicies.clone().into_iter().filter(|j| j != index));
            s!(secret * lambda)
        })
        .fold(s!(0), |acc, contribution| s!(acc + contribution))
}

#[cfg(test)]
mod test {
    use crate::{g, marker::Normal, poly, Point, G};

    use super::*;

    #[test]
    fn test_lagrange_lambda() {
        let res = s!((1 * 4 * 5) / { s!((1 - 2) * (4 - 2) * (5 - 2)).non_zero().unwrap() });
        assert_eq!(
            res,
            eval_basis_poly_at_0(s!(2), [s!(1), s!(4), s!(5)].into_iter())
        );
    }

    #[test]
    fn test_add_poly() {
        let poly1 = vec![g!(1 * G), g!(2 * G), g!(3 * G)];
        let poly2 = vec![g!(8 * G), g!(5 * G), g!(11 * G)];

        let addition = poly::point::add(&poly1, &poly2);
        assert_eq!(addition, vec![g!(9 * G), g!(7 * G), g!(14 * G)])
    }

    #[test]
    fn test_add_poly_unequal_len() {
        let poly1 = vec![g!(1 * G)];
        let poly2 = vec![g!(8 * G), g!(5 * G)];
        let addition = poly::point::add(&poly1, &poly2);
        assert_eq!(addition, vec![g!(9 * G), g!(5 * G)]);

        let poly1 = vec![g!(3 * G), g!(1 * G)];
        let poly2 = vec![g!(5 * G)];
        let addition = poly::point::add(&poly1, &poly2);
        assert_eq!(addition, vec![g!(8 * G), g!(1 * G)]);
    }

    #[test]
    fn test_recover_public_poly() {
        let poly = vec![g!(1 * G), g!(2 * G), g!(3 * G)];
        let indicies = vec![s!(1).public(), s!(3).public(), s!(2).public()];
        let points = indicies
            .clone()
            .into_iter()
            .map(|index| {
                (
                    index,
                    poly::point::eval(&poly, index.public())
                        .normalize()
                        .non_zero()
                        .unwrap(),
                )
            })
            .collect::<Vec<_>>();

        let interpolation = poly::point::interpolate(points);
        assert_eq!(interpolation, poly)
    }

    #[test]
    fn test_recover_overdetermined_poly() {
        let poly = vec![g!(1 * G), g!(2 * G), g!(3 * G)];
        let indicies = vec![
            s!(1).public(),
            s!(2).public(),
            s!(3).public(),
            s!(4).public(),
            s!(5).public(),
        ];
        let points = indicies
            .clone()
            .into_iter()
            .map(|index| {
                (
                    index,
                    poly::point::eval(&poly, index.public())
                        .normalize()
                        .non_zero()
                        .unwrap(),
                )
            })
            .collect::<Vec<_>>();

        let interpolation = poly::point::interpolate(points);

        let (interpolated_coeffs, zero_coeffs) = interpolation.split_at(poly.len());
        let n_extra_points = indicies.len() - poly.len();
        assert_eq!(
            (0..n_extra_points)
                .map(|_| Point::<Normal, Public, Zero>::zero().public().normalize())
                .collect::<Vec<_>>(),
            zero_coeffs.to_vec()
        );
        assert_eq!(interpolated_coeffs, poly);
    }

    #[test]
    fn test_reconstruct_shared_secret() {
        let scalar_poly = vec![s!(42), s!(53), s!(64)];
        let indicies = vec![s!(1), s!(2), s!(3)];

        let secret_shares: Vec<_> = indicies
            .clone()
            .into_iter()
            .map(|index| (index, poly::scalar::eval(&scalar_poly, index)))
            .collect();

        let reconstructed_secret = reconstruct_shared_secret(secret_shares);
        assert_eq!(scalar_poly[0], reconstructed_secret);
    }
}
