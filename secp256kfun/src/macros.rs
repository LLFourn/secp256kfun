/// Scalar expression macro.
///
/// Like [`g!`] except that the output of the expression is a [`Scalar`] rather than a [`Point`].
///
/// [`Scalar`]: crate::Scalar
/// [`Point`]: crate::Point
/// [`g!`]: crate::g
#[macro_export]
macro_rules! s {
    ($($t:tt)*) => {{
        $crate::arithmetic_macros::gen_s!($crate $($t)*)
    }}
}

/// Group operation expression macro.
///
/// The `g!` macro lets you express scalar multiplications and group operations conveniently
/// following standard [order of operations]. This compiles down to operations from the [`op`]
/// module. Apart from being far more readable, the idea is that `g!` will (or may in the future)
/// compile to more efficient operations than if you were to manually call the functions from [`op`]
/// yourself.
///
/// Note you can but often don't need to put a `&` in front of the terms in the expression.
///
/// # Syntax and operations
///
/// The expression supports the following operations:
///
/// - `<scalar> * <point>` multiplies the `point` by `scalar`
/// - `<point> + <point>` adds two points
/// - `<point> - <point>` subtracts one point from another
/// - `<scalar_iter> .* <point_iter>` does a [dot product](https://en.wikipedia.org/wiki/Dot_product)
///    between a list of points and scalars. If one list is shorter than the other then the excess
///    points or scalars will be multiplied by 0. See [`op::point_scalar_dot_product`].
///
/// The terms of the expression can be any variable followed by simple method calls, attribute
/// access etc. If your term involves more expressions (anything involving specifying types using
/// `::`) then you can use `{..}` to surround arbitrary expressions. You can also use `(..)` to
/// group arithmetic expressions to override the usual operation order.
///
/// # Examples
///
/// Simple scalar multiplication by [`G`] but will work with any [`Point`]
/// ```
/// use secp256kfun::{g, Scalar, G};
/// let x = Scalar::random(&mut rand::thread_rng());
/// let X = g!(x * G);
/// ```
///
/// A more complicated set of expressions.
/// ```
/// # use secp256kfun::{g, Point, Scalar, G};
/// let x = Scalar::random(&mut rand::thread_rng());
/// let y = Scalar::random(&mut rand::thread_rng());
/// let H = Point::random(&mut rand::thread_rng());
/// let minus = g!(x * G - y * H);
/// let plus = g!(x * G + y * H);
/// assert_eq!(g!(plus + minus), g!(2 * x * G)); // this will do 2 * x first
/// assert_eq!(g!(42 * (G + H)), g!((42 * G + 42 * H)));
/// ```
///
/// You may access attributes and call methods:
///
/// ```
/// # use secp256kfun::{g, Point, Scalar, G};
/// struct DoMul {
///     scalar: Scalar,
///     point: Point,
/// }
///
/// let mul = DoMul {
///     scalar: Scalar::random(&mut rand::thread_rng()),
///     point: Point::random(&mut rand::thread_rng()),
/// };
///
/// let result = g!(mul.scalar * mul.point);
/// assert_eq!(g!(mul.scalar.invert() * result), mul.point);
/// ```
///
/// You can put an arbitrary expressions inside `{...}`
///
/// ```
/// # use secp256kfun::{g, Point, Scalar, G};
/// let random_point = g!({ Scalar::random(&mut rand::thread_rng()) } * G);
/// ```
///
/// [`double_mul`]: crate::op::double_mul
/// [`G`]: crate::G
/// [`Point`]: crate::Point
/// [`op`]: crate::op
/// [order of operations]: https://en.wikipedia.org/wiki/Order_of_operations
/// [`op::point_scalar_dot_product`]: crate::op::point_scalar_dot_product
#[macro_export]
macro_rules! g {
    ($($t:tt)*) => {{
        $crate::arithmetic_macros::gen_g!($crate $($t)*)
    }}
}

/// Macro to make nonce derivation clear and explicit.
///
/// Nonce derivation is a sensitive action where mistakes can have catastrophic
/// consequences. This macro helps to make it clear for which secret the nonce
/// is being produced and what public input are being used to make sure no two
/// nonce values are the same (even when using generating the nonce
/// deterministically). For example, if you are implementing a signature scheme,
/// then the message you are signing would go into `public` and the secret
/// signign key would go into `secret`.
///
/// This macro compiles to a call to [`NonceGen::begin_derivation`].
///
/// # Examples
///
/// Derive a nonce deterministically. This example shouldn't be taken
/// literally. What you actually pass here to `secret` and `public` is dependent
/// on the cryptographic scheme and is crucial to get right.
///
/// ```
/// use secp256kfun::{Scalar, derive_nonce, Tag, nonce};
/// use sha2::Sha256;
/// let secret_scalar = Scalar::random(&mut rand::thread_rng());
/// let nonce_gen = nonce::Deterministic::<Sha256>::default().tag(b"my-protocol");
/// let r = derive_nonce!(
///     nonce_gen => nonce_gen,
///     secret => &secret_scalar,
///     public => [b"public-inputs-to-the-algorithm".as_ref()]
/// );
/// ```
/// [`NonceGen::begin_derivation`]: crate::nonce::NonceGen::begin_derivation
#[macro_export]
macro_rules! derive_nonce {
    (
        nonce_gen => $nonce_gen:expr,
        secret => $secret:expr,
        public => [$($public:expr),+]$(,)?
    ) => {{
        use $crate::hash::HashAdd;
        #[allow(unused_imports)]
        use core::borrow::Borrow;
        use $crate::nonce::NonceGen;
        Scalar::from_hash(
            $nonce_gen.begin_derivation($secret.borrow())$(.add($public))+
        )
    }}
}

/// Macro to derive a rng for producing multiple nonces.
///
/// This works like [`derive_nonce`] except that it produces an rng with the output rather than a
/// scalar.
///
/// # Examples
///
/// ```
/// use secp256kfun::{Scalar, derive_nonce_rng, Tag, nonce};
/// use sha2::Sha256;
/// let secret_scalar = Scalar::random(&mut rand::thread_rng());
/// let nonce_gen = nonce::Deterministic::<Sha256>::default().tag(b"my-protocol");
/// let mut rng = derive_nonce_rng!(
///     nonce_gen => nonce_gen,
///     secret => &secret_scalar,
///     public => [b"public-inputs-to-the-algorithm".as_ref()],
///     seedable_rng => rand::rngs::StdRng
/// );
/// let r1 = Scalar::random(&mut rng);
/// let r2 = Scalar::random(&mut rng);
/// ```
///
/// [`derive_nonce`]: crate::derive_nonce
#[macro_export]
macro_rules! derive_nonce_rng {
    (
        nonce_gen => $nonce_gen:expr,
        secret => $secret:expr,
        public => [$($public:expr),+],
        seedable_rng => $rng:ty$(,)?
    ) => {{
        use $crate::hash::HashAdd;
        use core::borrow::Borrow;
        use $crate::nonce::NonceGen;
        use $crate::rand_core::SeedableRng;
        use $crate::digest::FixedOutput;

        let hash = $nonce_gen.begin_derivation($secret.borrow())$(.add($public))+;
        <$rng>::from_seed(hash.finalize_fixed().into())
    }}
}

#[doc(hidden)]
#[macro_export]
macro_rules! impl_debug {
    (fn to_bytes$(<$($tpl:ident  $(: $tcl:ident)?),*>)?($self:ident : &$type_name:ident$(<$($tpr:path),+>)?) -> $($tail:tt)*) => {
        impl$(<$($tpl $(:$tcl)?),*>)? core::fmt::Debug for $type_name$(<$($tpr),+>)? {
            /// Formats the type as hex and any markers on the type.
            fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                let $self = &self;
                write!(f, "{}", stringify!($type_name))?;
                $(
                    write!(f, "<")?;
                    $crate::impl_debug!(@recursive_print f, $(core::any::type_name::<$tpr>().rsplit("::").next().unwrap()),*);
                    write!(f, ">")?;
                )?
                    write!(f, "(")?;
                $crate::impl_debug!(@output f, $self, $($tail)*);
                write!(f, ")")?;
                Ok(())
            }
        }
    };
    (@output $f:ident, $self:ident, Result<$(&)?[u8;$len:literal], &str> $block:block) => {
        let res: Result<[u8;$len], &str> = $block;
        match res {
            Ok(bytes) => {
                for byte in bytes.iter() {
                    write!($f, "{:02x}", byte)?
                }
            },
            Err(string) => {
                write!($f, "{}", string)?
            }
        }
    };
    (@output $f:ident, $self:ident, $(&)?[u8;$len:literal] $block:block) => {
        let bytes = $block;
        for byte in bytes.iter() {
            write!($f, "{:02x}", byte)?
        }
    };
    (@recursive_print $f:ident, $next:expr, $($tt:tt)+) => {
        $f.write_str($next)?;
        $f.write_str(",")?;
        $crate::impl_debug!(@recursive_print $f, $($tt)+)
    };
    (@recursive_print $f:ident, $next:expr) => {
        $f.write_str($next)?;
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! impl_display {
    (fn to_bytes$(<$($tpl:ident  $(: $tcl:ident)?),*>)?($self:ident : &$type:path) -> $(&)?[u8;$len:literal] $block:block) => {

        impl$(<$($tpl $(:$tcl)?),*>)? core::fmt::Display for $type {
            /// Displays as hex.
            fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                let $self = &self;
                let bytes = $block;
                for byte in bytes.iter() {
                    write!(f, "{:02x}", byte)?
                }
                Ok(())
            }
        }
    }
}

#[macro_export]
#[doc(hidden)]
macro_rules! impl_serialize {
    (fn to_bytes$(<$($tpl:ident  $(: $tcl:ident)?),*>)?($self:ident : &$type:path) -> $(&)?[u8;$len:literal] $block:block) => {
        #[cfg(feature = "serde")]
        #[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
        impl$(<$($tpl $(:$tcl)?),*>)? $crate::serde::Serialize for $type {
            fn serialize<Ser: $crate::serde::Serializer>(&self, serializer: Ser) -> Result<Ser::Ok, Ser::Error> {
                use $crate::serde::ser::SerializeTuple;
                let $self = &self;
                let bytes = $block;

                #[cfg(feature = "alloc")]
                {
                    use $crate::hex;
                    if serializer.is_human_readable() {
                        return serializer.serialize_str(&hex::encode(&bytes[..]))
                    }
                }

                //NOTE: idea taken from https://github.com/dalek-cryptography/curve25519-dalek/pull/297/files
                let mut tup = serializer.serialize_tuple($len)?;
                for byte in bytes.iter() {
                    tup.serialize_element(byte)?;
                }
                tup.end()
            }
        }

        #[cfg(feature = "bincode")]
        #[cfg_attr(docsrs, doc(cfg(feature = "bincode")))]
        impl$(<$($tpl $(:$tcl)?),*>)? $crate::bincode::Encode for $type {
            fn encode<E: $crate::bincode::enc::Encoder>(&self, encoder: &mut E) -> Result<(), $crate::bincode::error::EncodeError> {
                use $crate::bincode::enc::write::Writer;
                let $self = &self;
                let bytes = $block;
                encoder.writer().write(bytes.as_ref())
            }
        }
    }
}

#[macro_export]
#[doc(hidden)]
macro_rules! impl_display_serialize {
    ($($tt:tt)+) => {
        $crate::impl_serialize!($($tt)+);
        $crate::impl_display!($($tt)+);
    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! impl_display_debug_serialize {
    ($($tt:tt)+) => {
        $crate::impl_display_serialize!($($tt)+);
        $crate::impl_debug!($($tt)*);
    };
}

/// Implements Display, FromStr, Serialize and Deserialize for something that
/// can be represented as a fixed length byte array
#[macro_export]
#[doc(hidden)]
macro_rules! impl_fromstr_deserialize {
        (
        name => $name:literal,
        fn from_bytes$(<$($tpl:ident  $(: $tcl:ident)?),*>)?($input:ident : [u8;$len:literal]) ->  Option<$type:path> $block:block
    ) => {
        impl$(<$($tpl $(:$tcl)?),*>)? core::str::FromStr for $type  {
            type Err = $crate::hex::HexError;

            /// Parses the string as hex and interprets tries to convert the
            /// resulting byte array into the desired value.
            fn from_str(hex: &str) -> Result<$type , $crate::hex::HexError> {
                use $crate::hex::hex_val;
                if hex.len() % 2 == 1 {
                    Err($crate::hex::HexError::InvalidHex)
                } else if $len * 2 != hex.len() {
                    Err($crate::hex::HexError::InvalidLength)
                } else {
                    let mut buf = [0u8; $len];

                    for (i, hex_byte) in hex.as_bytes().chunks(2).enumerate() {
                        buf[i] = hex_val(hex_byte[0])? << 4 | hex_val(hex_byte[1])?
                    }

                    let $input = buf;
                    #[allow(clippy::redundant_closure_call)]
                    let result = (|| -> Option<$type> {$block})();
                    result.ok_or($crate::hex::HexError::InvalidEncoding)
                }
            }
        }


        #[cfg(feature = "serde")]
        #[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
        impl<'de, $($($tpl $(: $tcl)?),*)?> $crate::serde::Deserialize<'de> for $type  {
            fn deserialize<Deser: $crate::serde::Deserializer<'de>>(
                deserializer: Deser,
            ) -> Result<$type , Deser::Error> {

                #[cfg(feature = "alloc")]
                {
                    if deserializer.is_human_readable() {
                        #[allow(unused_parens)]
                        struct HexVisitor$(<$($tpl),*>)?$((core::marker::PhantomData<($($tpl),*)> ))?;
                        impl<'de, $($($tpl $(: $tcl)?),*)?> $crate::serde::de::Visitor<'de> for HexVisitor$(<$($tpl),*>)? {
                            type Value = $type ;
                            fn expecting(
                                &self,
                                f: &mut core::fmt::Formatter,
                            ) -> core::fmt::Result {
                                write!(f, "a valid {}-byte hex encoded {}", $len, $name)?;
                                Ok(())
                            }

                            fn visit_str<E: $crate::serde::de::Error>(self, v: &str) -> Result<$type , E> {
                                use $crate::hex::HexError::*;
                                <$type  as core::str::FromStr>::from_str(v).map_err(|e| match e {
                                    InvalidLength => E::invalid_length(v.len() / 2, &self),
                                    InvalidEncoding => E::invalid_value($crate::serde::de::Unexpected::Str(v), &self),
                                    InvalidHex => E::custom("invalid hex")
                                })
                            }
                        }

                        #[allow(unused_parens)]
                        return deserializer.deserialize_str(HexVisitor$((core::marker::PhantomData::<($($tpl),*)>))?);
                    }
                }

                {
                    #[allow(unused_parens)]
                    struct BytesVisitor$(<$($tpl),*>)?$((core::marker::PhantomData<($($tpl),*)> ))?;

                    impl<'de, $($($tpl $(: $tcl)?),*)?> $crate::serde::de::Visitor<'de> for BytesVisitor$(<$($tpl),*>)? {
                        type Value = $type ;

                        fn expecting(
                            &self,
                            f: &mut core::fmt::Formatter,
                        ) -> core::fmt::Result {
                            write!(f, "a valid {}-byte encoding of a {}", $len, $name)?;
                            Ok(())
                        }

                        fn visit_seq<A>(self, mut seq: A) -> Result<$type , A::Error>
                        where A: $crate::serde::de::SeqAccess<'de> {

                            let mut $input = [0u8; $len];
                            for i in 0..$len {
                                $input[i] = seq.next_element()?
                                               .ok_or_else(|| $crate::serde::de::Error::invalid_length(i, &self))?;
                            }

                            #[allow(clippy::redundant_closure_call)]
                            let result = (|| -> Option<$type> { $block }());
                            result.ok_or($crate::serde::de::Error::custom(format_args!("invalid byte encoding, expected {}", &self as &dyn $crate::serde::de::Expected)))
                        }
                    }

                    #[allow(unused_parens)]
                    deserializer.deserialize_tuple($len, BytesVisitor$((core::marker::PhantomData::<($($tpl),*)>))?)
                }
            }
        }

        #[cfg(feature = "bincode")]
        #[cfg_attr(docsrs, doc(cfg(feature = "bincode")))]
        impl$(<$($tpl $(:$tcl)?),*>)? $crate::bincode::de::Decode for $type {
            fn decode<D: $crate::bincode::de::Decoder>(decoder: &mut D) -> Result<Self, $crate::bincode::error::DecodeError> {
                use $crate::bincode::de::read::Reader;
                let mut $input = [0u8; $len];
                decoder.reader().read(&mut $input)?;
                #[allow(clippy::redundant_closure_call)]
                let result = (|| -> Option<$type> { $block }());
                #[cfg(feature = "alloc")]
                return result.ok_or($crate::bincode::error::DecodeError::OtherString(format!("Invalid {}-byte encoding of a {}", $len, $name)));
                #[cfg(not(feature = "alloc"))]
                return result.ok_or($crate::bincode::error::DecodeError::Other(stringify!(Invalid $len-byte encoding of a $name)))
            }
        }

        #[cfg(feature = "bincode")]
        #[cfg_attr(docsrs, doc(cfg(feature = "bincode")))]
        impl<'de, $($($tpl $(:$tcl)?),*)?> $crate::bincode::BorrowDecode<'de> for $type {
            fn borrow_decode<D: $crate::bincode::de::BorrowDecoder<'de>>(
                decoder: &mut D,
            ) -> core::result::Result<Self, $crate::bincode::error::DecodeError> {
                $crate::bincode::Decode::decode(decoder)
            }
        }
    };
}
