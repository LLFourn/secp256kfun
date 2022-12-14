#![cfg(all(feature = "libsecp_compat", feature = "alloc", feature = "proptest"))]
#![allow(non_snake_case)]
#[cfg(not(target_arch = "wasm32"))]
mod against_c_lib {
    use proptest::prelude::*;
    use secp256k1::{All, PublicKey, Secp256k1, SecretKey};
    use secp256kfun::{g, marker::*, op::double_mul, s, Point, Scalar, G};

    lazy_static::lazy_static! {
        static ref SECP: Secp256k1<All> = Secp256k1::new();
    }

    proptest! {
        #[test]
        fn point_multiplication(s1 in any::<[u8;32]>(), s2 in any::<[u8;32]>()) {

            // Multiply a generator by scalar for both libraries and test equality
            let (point_1, secp_pk_1) = {
                let point_1 = g!({ Scalar::from_bytes_mod_order(s1.clone()) } * G)
                    .normalize().non_zero()
                    .unwrap();

                let secp_pk_1 =
                    PublicKey::from_secret_key(&*SECP, &SecretKey::from_slice(&s1).unwrap());

                prop_assert_eq!(
                    &point_1.to_bytes_uncompressed()[..],
                    &secp_pk_1.serialize_uncompressed()[..]
                );
                (point_1, secp_pk_1)
            };

            // Multiply the resulting points by another scalar and test equality
            {
                let point_2 = g!({ Scalar::from_bytes_mod_order(s2.clone()) } * point_1)
                    .normalize().non_zero()
                    .unwrap();
                let secp_pk_2 = {
                    let scalar = secp256k1::Scalar::from_be_bytes(s2).unwrap();
                    secp_pk_1.clone().mul_tweak(&*SECP, &scalar).unwrap()
                };
                prop_assert_eq!(
                    &point_2.to_bytes_uncompressed()[..],
                    &secp_pk_2.serialize_uncompressed()[..]
                );
            }
        }

        #[test]
        fn vartime_double_mul(scalar_H in any::<[u8;32]>(), y in any::<[u8;32]>(), x in any::<[u8;32]>()) {
            let result = {
                let H = g!({ Scalar::from_bytes_mod_order(scalar_H.clone()) } * G);
                double_mul(
                    &Scalar::from_bytes_mod_order(x.clone()).public(),
                    G,
                    &Scalar::from_bytes_mod_order(y.clone()).public(),
                    &H,
                )
                    .normalize().non_zero()
                    .unwrap()
            };

            let result_secp = {
                let H = PublicKey::from_secret_key(&*SECP, &SecretKey::from_slice(&scalar_H).unwrap());
                let x_G = PublicKey::from_secret_key(&*SECP, &SecretKey::from_slice(&x).unwrap());
                let scalar = secp256k1::Scalar::from_be_bytes(y).unwrap();
                let y_H = H.clone().mul_tweak(&*SECP, &scalar).unwrap();
                x_G.combine(&y_H).unwrap()
            };

            prop_assert_eq!(
                &result.to_bytes_uncompressed()[..],
                &result_secp.serialize_uncompressed()[..]
            )
        }

        #[test]
        fn point_addition(scalar_1 in any::<[u8;32]>()) {
            let secp_pk_1 =
                PublicKey::from_secret_key(&*SECP, &SecretKey::from_slice(&scalar_1).unwrap());
            let point_1 = g!({ Scalar::from_bytes_mod_order(scalar_1.clone()) } * G);


            prop_assert_eq!(
                (g!(point_1 + point_1))
                    .normalize().non_zero()
                    .unwrap()
                    .to_bytes_uncompressed(),
                secp_pk_1
                    .combine(&secp_pk_1)
                    .unwrap()
                    .serialize_uncompressed()
            );
        }

        #[test]
        fn scalar_ops(bytes_1 in any::<[u8;32]>(), bytes_2 in any::<[u8;32]>()) {
            let scalar_1 = Scalar::from_bytes_mod_order(bytes_1.clone());
            let scalar_2 = Scalar::from_bytes_mod_order(bytes_2.clone());
            let sk_1 = &SecretKey::from_slice(&bytes_1).unwrap();

            prop_assert_eq!(&scalar_1.to_bytes()[..], &sk_1[..]);

            prop_assert_eq!(
                &(s!(scalar_1 + scalar_2)).to_bytes()[..],
                &{
                    let res = sk_1.clone();
                    let scalar = secp256k1::Scalar::from_be_bytes(bytes_2).unwrap();
                    let res = res.add_tweak(&scalar).unwrap();
                    res
                }[..]
            );

            prop_assert_eq!(
                &(s!(scalar_1 * scalar_2)).to_bytes()[..],
                &{
                    let scalar = secp256k1::Scalar::from_be_bytes(bytes_2).unwrap();
                    sk_1.clone().mul_tweak(&scalar).unwrap()
                }[..]
            )
        }

        #[test]
        fn scalar_negation(bytes in any::<[u8;32]>()) {
            let sk = SecretKey::from_slice(&bytes).unwrap().negate();
            let scalar = Scalar::from_bytes_mod_order(bytes.clone());
            prop_assert_eq!(&(-scalar).to_bytes()[..], &sk[..]);
        }

        #[test]
        fn point_ord(point1 in any::<Point>(), point2 in any::<Point>()) {
            prop_assert_eq!(
                point1.cmp(&point2),
                PublicKey::from(point1).cmp(&PublicKey::from(point2))
            );
        }

        #[test]
        fn scalar_ord(scalar1 in any::<Scalar<Public, Zero>>(), scalar2 in any::<Scalar<Public,Zero>>()) {
            prop_assert_eq!(
                scalar1.cmp(&scalar2),
                secp256k1::Scalar::from(scalar1).cmp(&secp256k1::Scalar::from(scalar2))
            );
        }
    }
}
