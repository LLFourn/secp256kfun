#![allow(non_snake_case)]
#[cfg(not(target_arch = "wasm32"))]
mod test {
    use secp256k1::{PublicKey, SecretKey};
    use secp256kfun::{g, marker::*, op::double_mul, s, Scalar, G};

    fn rand_32_bytes() -> [u8; 32] {
        use rand::RngCore;
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        bytes
    }

    #[test]
    fn point_multiplication() {
        let secp = secp256k1::Secp256k1::new();

        // Multiply a generator by scalar for both libraries and test equality
        let (point_1, secp_pk_1) = {
            let scalar_1 = rand_32_bytes();
            let point_1 = g!({ Scalar::from_bytes_mod_order(scalar_1.clone()) } * G)
                .mark::<(Normal, NonZero)>()
                .unwrap();

            let secp_pk_1 =
                PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&scalar_1).unwrap());

            assert_eq!(
                &point_1.to_bytes_uncompressed()[..],
                &secp_pk_1.serialize_uncompressed()[1..]
            );
            (point_1, secp_pk_1)
        };

        // Multiply the resulting points by another scalar and test equality
        {
            let scalar_2 = rand_32_bytes();
            let point_2 = g!({ Scalar::from_bytes_mod_order(scalar_2.clone()) } * point_1)
                .mark::<(Normal, NonZero)>()
                .unwrap();
            let secp_pk_2 = {
                let mut secp_pk_2 = secp_pk_1.clone();
                secp_pk_2.mul_assign(&secp, &scalar_2).unwrap();
                secp_pk_2
            };
            assert_eq!(
                &point_2.to_bytes_uncompressed()[..],
                &secp_pk_2.serialize_uncompressed()[1..]
            );
        }
    }

    #[test]
    fn vartime_double_mul() {
        let secp = secp256k1::Secp256k1::new();
        let scalar_H = rand_32_bytes();
        let y = rand_32_bytes();
        let x = rand_32_bytes();

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
            let H = PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&scalar_H).unwrap());
            let x_G = PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&x).unwrap());
            let mut y_H = H.clone();
            y_H.mul_assign(&secp, &y).unwrap();
            x_G.combine(&y_H).unwrap()
        };

        assert_eq!(
            &result.to_bytes_uncompressed()[..],
            &result_secp.serialize_uncompressed()[1..],
        )
    }

    #[test]
    fn point_addition() {
        let secp = secp256k1::Secp256k1::new();

        let scalar_1 = rand_32_bytes();
        let point_1 = g!({ Scalar::from_bytes_mod_order(scalar_1.clone()) } * G);
        let secp_pk_1 =
            PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&scalar_1).unwrap());

        assert_eq!(
            (g!(point_1 + point_1))
                .mark::<(Normal, NonZero)>()
                .unwrap()
                .to_bytes_uncompressed()[..],
            secp_pk_1
                .combine(&secp_pk_1)
                .unwrap()
                .serialize_uncompressed()[1..]
        );
    }

    #[test]
    fn scalar_ops() {
        let bytes_1 = rand_32_bytes();
        let bytes_2 = rand_32_bytes();
        let scalar_1 = Scalar::from_bytes_mod_order(bytes_1.clone());
        let scalar_2 = Scalar::from_bytes_mod_order(bytes_2.clone());
        let sk_1 = &SecretKey::from_slice(&bytes_1).unwrap();

        assert_eq!(&scalar_1.to_bytes()[..], &sk_1[..]);

        assert_eq!(
            &(s!(scalar_1 + scalar_2)).to_bytes()[..],
            &{
                let mut res = sk_1.clone();
                res.add_assign(&bytes_2[..]).unwrap();
                res
            }[..]
        );

        assert_eq!(
            &(s!(scalar_1 * scalar_2)).to_bytes()[..],
            &{
                let mut res = sk_1.clone();
                res.mul_assign(&bytes_2[..]).unwrap();
                res
            }[..]
        )
    }

    #[test]
    fn scalar_inversion() {
        // we have to test against this grin secp because that's the one that exposes it
        use secp256k1zkp::key::SecretKey;
        let secp = secp256k1zkp::Secp256k1::new();
        let bytes = rand_32_bytes();
        let mut sk = SecretKey::from_slice(&secp, &bytes).unwrap();
        let scalar = Scalar::from_bytes_mod_order(bytes.clone())
            .mark::<NonZero>()
            .unwrap();
        sk.inv_assign(&secp).unwrap();
        assert_eq!(&scalar.invert().to_bytes()[..], &sk[..]);
    }

    #[test]
    fn scalar_negation() {
        use secp256k1zkp::key::SecretKey;
        let secp = secp256k1zkp::Secp256k1::new();
        let bytes = rand_32_bytes();
        let mut sk = SecretKey::from_slice(&secp, &bytes).unwrap();
        let scalar = Scalar::from_bytes_mod_order(bytes.clone());
        sk.neg_assign(&secp).unwrap();
        assert_eq!(&(-scalar).to_bytes()[..], &sk[..]);
    }
}
