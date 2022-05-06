#![allow(non_snake_case)]
#[cfg(not(target_arch = "wasm32"))]
mod against_c_lib {
    use proptest::prelude::*;
    use secp256k1::{PublicKey, SecretKey, SECP256K1 as SECP};
    use secp256kfun::{g, marker::*, op::double_mul, s, Scalar, G};

    proptest! {
        #[test]
        fn point_multiplication(s1 in any::<[u8;32]>(), s2 in any::<[u8;32]>()) {

            // Multiply a generator by scalar for both libraries and test equality
            let (point_1, secp_pk_1) = {
                let point_1 = g!({ Scalar::from_bytes_mod_order(s1.clone()) } * G)
                    .mark::<(Normal, NonZero)>()
                    .unwrap();

                let secp_pk_1 =
                    PublicKey::from_secret_key(SECP, &SecretKey::from_slice(&s1).unwrap());

                prop_assert_eq!(
                    &point_1.to_bytes_uncompressed()[..],
                    &secp_pk_1.serialize_uncompressed()[..]
                );
                (point_1, secp_pk_1)
            };

            // Multiply the resulting points by another scalar and test equality
            {
                let point_2 = g!({ Scalar::from_bytes_mod_order(s2.clone()) } * point_1)
                    .mark::<(Normal, NonZero)>()
                    .unwrap();
                let secp_pk_2 = {
                    let mut secp_pk_2 = secp_pk_1.clone();
                    secp_pk_2.mul_assign(SECP, &s2).unwrap();
                    secp_pk_2
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
                    &Scalar::from_bytes_mod_order(x.clone()).mark::<Public>(),
                    G,
                    &Scalar::from_bytes_mod_order(y.clone()).mark::<Public>(),
                    &H,
                )
                    .mark::<(Normal, NonZero)>()
                    .unwrap()
            };

            let result_secp = {
                let H = PublicKey::from_secret_key(SECP, &SecretKey::from_slice(&scalar_H).unwrap());
                let x_G = PublicKey::from_secret_key(SECP, &SecretKey::from_slice(&x).unwrap());
                let mut y_H = H.clone();
                y_H.mul_assign(SECP, &y).unwrap();
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
                PublicKey::from_secret_key(SECP, &SecretKey::from_slice(&scalar_1).unwrap());
            let point_1 = g!({ Scalar::from_bytes_mod_order(scalar_1.clone()) } * G);


            prop_assert_eq!(
                (g!(point_1 + point_1))
                    .mark::<(Normal, NonZero)>()
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
                    let mut res = sk_1.clone();
                    res.add_assign(&bytes_2[..]).unwrap();
                    res
                }[..]
            );

            prop_assert_eq!(
                &(s!(scalar_1 * scalar_2)).to_bytes()[..],
                &{
                    let mut res = sk_1.clone();
                    res.mul_assign(&bytes_2[..]).unwrap();
                    res
                }[..]
            )
        }

        #[test]
        fn scalar_negation(bytes in any::<[u8;32]>()) {
            let mut sk = SecretKey::from_slice(&bytes).unwrap();
            let scalar = Scalar::from_bytes_mod_order(bytes.clone());
            sk.negate_assign();
            prop_assert_eq!(&(-scalar).to_bytes()[..], &sk[..]);
        }
    }
}
