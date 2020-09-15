#[doc(hidden)]
#[macro_export]
macro_rules! _s {
    (@dot [$($a:tt)*] [$($aa:ident).+] . $attr:ident $($t:tt)*) => {
        $crate::_s!(@dot [$($a)*] [$($aa).+.$attr] $($t)*)
    };
    (@dot [$($a:tt)*] [$($aa:ident).+] $($t:tt)*) => {
        // no more dots to process to join them all together
        $crate::_s!(@next [{$($aa).+.borrow()} $($a)*] $($t)*)
    };
    (@scalar [$($a:tt)*] & $($t:tt)+) => {
        core::compile_error!("Do not use ‘&’ in s!(...) expression");
    };
    (@scalar [$($a:tt)*] - $($t:tt)+) => {
        $crate::_s!(@scalar [neg $($a)*] $($t)+)
    };
    (@scalar [$($a:tt)*] $scalar:ident $($t:tt)*) => {
        $crate::_s!(@dot [$($a)*] [$scalar] $($t)*)
    };
    (@scalar [$($a:tt)*] 0 $($t:tt)*) => {
        $crate::_s!(@next [{$crate::Scalar::zero()} $($a)*] $($t)*)
    };
    (@scalar [$($a:tt)*] $num:literal $($t:tt)*) => {
        $crate::_s!(@next [{{
        // hack to check at compile time the thing is non-zero
        let _ = [(); (($num as u32).count_ones() as usize) - 1];
        $crate::Scalar::<$crate::marker::Secret, $crate::marker::NonZero>::from_non_zero_u32(
            unsafe { core::num::NonZeroU32::new_unchecked($num) },
        )
    }} $($a)*] $($t)*)
    };
    (@scalar [$($a:tt)*] $block:block $($t:tt)*) => {
        $crate::_s!(@next [$block $($a)*] $($t)*)
    };
    (@scalar [$($a:tt)*] ($($subexpr:tt)+) $($t:tt)*) => {
        $crate::_s!(@next [{$crate::_s!(@scalar [] $($subexpr)+)} $($a)*] $($t)*)
    };

    (@next [$stack0:block neg $($a:tt)*] $($t:tt)*) => {
        $crate::_s!(@next [{core::ops::Neg::neg($stack0)} $($a)*] $($t)*)
    };

    (@next [$stack0:block $stack1:block mul $($a:tt)*] $($t:tt)*) => {
        $crate::_s!(@next [{$crate::op::scalar_mul($stack1.borrow(), $stack0.borrow())} $($a)*] $($t)*)
    };

    (@next [$stack0:block $($a:tt)*] * $($t:tt)+) => {
        $crate::_s!(@scalar [$stack0 mul $($a)*] $($t)*)
    };

    (@next [$stack0:block $stack1:block sub $($a:tt)*] $($t:tt)*) => {
        $crate::_s!(@next [{$crate::op::scalar_sub($stack1.borrow(), $stack0.borrow())} $($a)*] $($t)*)
    };

    (@next [$stack0:block $stack1:block add $($a:tt)*] $($t:tt)*) => {
        $crate::_s!(@next [{$crate::op::scalar_add($stack1.borrow(), $stack0.borrow())} $($a)*] $($t)*)
    };

    (@next [$stack0:block $($a:tt)*] - $($t:tt)+) => {
        $crate::_s!(@scalar [$stack0 sub $($a)*] $($t)+)
    };

    (@next [$stack0:block $($a:tt)*] + $($t:tt)+) => {
        $crate::_s!(@scalar [$stack0 add $($a)*] $($t)+)
    };

    (@next [$scalar:block]) => {
        #[allow(unused_braces)]
        $scalar
    };

    (@next [$scalar:block stringify]) => {
        #[allow(unused_braces)]
        stringify!($scalar)
    };
}

/// Scalar expression macro.
#[macro_export]
macro_rules! s {
    (DEBUG $($t:tt)*) => {{
        #[allow(unused_imports)]
        use core::borrow::Borrow;
        $crate::_s!(@scalar [stringify] $($t)*)
    }};
    ($($t:tt)*) => {{
        #[allow(unused_imports)]
        use core::borrow::Borrow;
        $crate::_s!(@scalar [] $($t)*)
    }}
}

#[doc(hidden)]
#[macro_export]
macro_rules! _g {
    (@scalar [$($a:tt)*] & $($t:tt)+) => {
        core::compile_error!("Do not use ‘&’ in g!(...) expression");
    };
    (@scalar [$($a:tt)*] - $($t:tt)+) => {
        $crate::_g!(@scalar [neg $($a)*] $($t)+)
    };
    (@scalar [$($a:tt)*] ($($expr:tt)+) * $($t:tt)+) => {
        $crate::_g!(@point [s {$crate::_s!(@scalar [] $($expr)+)}  $($a)*] $($t)+)
    };
    (@scalar [$($a:tt)*] $ident:ident $($t:tt)*) => {
        // We've got an identifier "foo" go and try to match foo.bar
        // we don't know if this is a scalar yet.
        $crate::_g!(@dot [$($a)*] [$ident] $($t)*)
    };
    (@scalar [$($a:tt)*] $block:block * $($t:tt)*) => {
        $crate::_g!(@point [s $block $($a)*] $($t)*)
    };
    (@scalar [$($a:tt)*] 0 * $($t:tt)+) => {
        $crate::_g!(@point [s {$crate::Scalar::zero()} $($a)*] $($t)+)
    };
    (@scalar [$($a:tt)*] $num:literal * $($t:tt)+) => {
        $crate::_g!(@point [s {{
        // hack to check at compile time the thing is non-zero
        let _ = [(); (($num as u32).count_ones() as usize) - 1];
        $crate::Scalar::<$crate::marker::Secret, $crate::marker::NonZero>::from_non_zero_u32(
            unsafe { core::num::NonZeroU32::new_unchecked($num) },
        )
    }} $($a)*] $($t)+)
    };
    (@scalar [$($a:tt)*] $($t:tt)+) => {
        // failed to find scalar look for point instead
        $crate::_g!(@point [$($a)*] $($t)+)
    };
    (@dot [$($a:tt)*] [$($aa:ident).+] . $attr:ident $($t:tt)*) => {
        $crate::_g!(@dot [$($a)*] [$($aa).+.$attr] $($t)*)
    };
    (@dot [$($a:tt)*] [$($aa:ident).+] * $($t:tt)*) => {
        // no more dots to process and we seem to have a scalar.
        // Join them together and look for a point.
        $crate::_g!(@point [s {$($aa).+.borrow()} $($a)*] $($t)*)
    };
    (@dot [$($a:tt)*] [$($aa:ident).+] $($t:tt)*) => {
        // no more dots to process and it looks like this was a point
        // so go onto the next operator
        $crate::_g!(@next [{$($aa).+.borrow()} $($a)*] $($t)*)
    };
    (@point [$($a:tt)*] $point:ident $($t:tt)*) => {
        $crate::_g!(@dot [$($a)*] [$point] $($t)*)
    };
    (@point [$($a:tt)*] $block:block $($t:tt)*) => {
        $crate::_g!(@next [$block $($a)*] $($t)*)
    };
    (@point [$($a:tt)*] ($($expr:tt)+) $($t:tt)*) => {
        $crate::_g!(@next [{ $crate::_g!(@scalar [] $($expr)+) } $($a)*] $($t)*)
    };
    (@next [$point0:block s $scalar0:block neg $($a:tt)*] $($t:tt)*) => {
        $crate::_g!(@next [$point0 s {core::ops::Neg::neg($scalar0.borrow())} $($a)*] $($t)*)
    };
    (@next [$point0:block neg $($a:tt)*] $($t:tt)*) => {
        $crate::_g!(@next [{core::ops::Neg::neg($point0)} $($a)*] $($t)*)
    };
    (@next [$point0:block s $scalar0:block $point1:block s $scalar1:block add $($a:tt)*] $($t:tt)*) => {

        $crate::_g!(@next [{
            $crate::op::double_mul(
                $scalar0.borrow(),
                $point0.borrow(),
                $scalar1.borrow(),
                $point1.borrow()
            )} $($a)*]  $($t)*)
    };
    (@next [$point0:block s $scalar0:block $point1:block s $scalar1:block sub $($a:tt)*] $($t:tt)*) => {
        $crate::_g!(@next [{
            $crate::op::double_mul(
                &core::ops::Neg::neg($scalar0),
                $point0.borrow(),
                $scalar1.borrow(),
                $point1.borrow()
            )} $($a)*]  $($t)*)
    };
    (@next [$point0:block $(s $scalar0:block)? $point1:block $(s $scalar1:block)? add $($a:tt)*] $($t:tt)*) => {
        $crate::_g!(@next [
            {$crate::op::point_add(
                $crate::_g!(@next [$point1 $(s $scalar1)?]).borrow(),
                $crate::_g!(@next [$point0 $(s $scalar0)?]).borrow()
            )} $($a)*] $($t)*)
    };
    (@next [$point0:block $(s $scalar0:block)? $point1:block $(s $scalar1:block)? sub $($a:tt)*] $($t:tt)*) => {
        $crate::_g!(@next [
            {$crate::op::point_sub(
                $crate::_g!(@next [$point1 $(s $scalar1)?]).borrow(),
                $crate::_g!(@next [$point0 $(s $scalar0)?]).borrow()
            )}
            $($a)*] $($t)*)
    };
    (@next [$point0:block s $scalar0:block $($a:tt)*] + $($t:tt)*) => {
        $crate::_g!(@scalar [$point0 s $scalar0 add $($a)*] $($t)*)
    };
    (@next [$point0:block $($a:tt)*] + $($t:tt)+) => {
        $crate::_g!(@scalar [$point0 add $($a)*] $($t)+)
    };
    (@next [$point0:block s $scalar0:block $($a:tt)*] - $($t:tt)+) => {
        $crate::_g!(@scalar [$point0 s $scalar0 sub $($a)*] $($t)+)
    };
    (@next [$point0:block $($a:tt)*] - $($t:tt)+) => {
        $crate::_g!(@scalar [$point0 sub $($a)*] $($t)+)
    };
    (@next [$point0:block s $scalar0:block]) => {
        $crate::op::scalar_mul_point($scalar0.borrow(), $point0.borrow())
    };
    (@next [$point0:block]) => {
        #[allow(unused_braces)]
        $point0
    }
}

/// Group operation expression macro.
///
/// The `g!` macro lets you express a set of scalar multiplications and group
/// additions/substraction. This compiles down to operations from the [`op`]
/// module. Apart from being far more readable, the idea is that `g!` will (or
/// may in the future) compile to more efficient operations than if you were to
/// manually call the functions from `op` yourself.
///
/// As a bonus, you don't need to put reference `&` makers on terms in `g!` this
/// is done automatically if necessary.
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
/// // note the parenthesis around the scalar sub expression
/// assert_eq!(g!(plus + minus), g!((2 * x) * G));
/// ```
///
/// You may access attributes:
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
/// ```
///
/// You can put an arbitrary expressions inside `{...}`
///
/// ```
/// # use secp256kfun::{g, Point, Scalar, G};
/// let x = Scalar::random(&mut rand::thread_rng());
/// let Xinv = g!({ x.invert() } * G);
/// assert_eq!(g!(x * Xinv), *G);
/// ```
///
/// [`double_mul`]: crate::op::double_mul
/// [`G`]: crate::G
/// [`Point`]: crate::Point
/// [`op`]: crate::op

#[macro_export]
macro_rules! g {
    ($($t:tt)+) => {{
        #[allow(unused_imports)]
        use core::borrow::Borrow;
        $crate::_g!(@scalar [] $($t)+) }};
}

/// Makes all tests within the block valid wasm32 tests as well with wasm_bindgen_test
#[doc(hidden)]
#[macro_export]
macro_rules! test_plus_wasm {
    ($($test:item)*) => {
        #[cfg(target_arch = "wasm32")]
        use wasm_bindgen_test::*;
        $(
            #[cfg_attr(not(target_arch = "wasm32"), test)]
            #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
            $test
         )*
    };
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
/// use secp256kfun::{Scalar, derive_nonce, hash::AddTag, nonce::{NonceGen,Deterministic}};
/// use sha2::Sha256;
/// let secret_scalar = Scalar::random(&mut rand::thread_rng());
/// let nonce_gen = Deterministic::<Sha256>::default().add_protocol_tag("my-protocol");
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
        public => [$($public:expr),+]
    ) => {{
        use $crate::hash::HashAdd;
        use core::borrow::Borrow;
        use $crate::nonce::NonceGen;
        Scalar::from_hash(
            $nonce_gen.begin_derivation($secret.borrow())$(.add($public.borrow()))+
        )
    }}
}

#[doc(hidden)]
#[macro_export]
macro_rules! impl_display_debug {
    (fn to_bytes$(<$($tpl:ident  $(: $tcl:ident)?),*>)?($self:ident : &$type_name:ident$(<$($tpr:path),+>)?) -> $($tail:tt)*) => {
        impl$(<$($tpl $(:$tcl)?),*>)? core::fmt::Display for $type_name$(<$($tpr),+>)? {
            /// Displays as hex.
            fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                let $self = &self;
                $crate::impl_display_debug!(@output f, $self, $($tail)*);
                Ok(())
            }
        }

        impl$(<$($tpl $(:$tcl)?),*>)? core::fmt::Debug for $type_name$(<$($tpr),+>)? {
            /// Formats the type as hex and any markers on the type.
            fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                let $self = &self;
                write!(f, "{}", stringify!($type_name))?;
                $(
                    write!(f, "<")?;
                    $crate::impl_display_debug!(@recursive_print f, $(core::any::type_name::<$tpr>().rsplit("::").next().unwrap()),*);
                    write!(f, ">")?;
                )?
                    write!(f, "(")?;
                $crate::impl_display_debug!(@output f, $self, $($tail)*);
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
        $crate::impl_display_debug!(@recursive_print $f, $($tt)+)
    };
    (@recursive_print $f:ident, $next:expr) => {
        $f.write_str($next)?;
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! impl_serialize {
    (fn to_bytes$(<$($tpl:ident  $(: $tcl:ident)?),*>)?($self:ident : &$type:path) -> $(&)?[u8;$len:literal] $block:block) => {
        #[cfg(feature = "serialization")]
        impl$(<$($tpl $(:$tcl)?),*>)? serde::Serialize for $type {
            fn serialize<Ser: serde::Serializer>(&self, serializer: Ser) -> Result<Ser::Ok, Ser::Error> {
                #[cfg(any(feature = "serialize_hex", test))]
                {
                    if serializer.is_human_readable() {
                        return serializer.collect_str(&self)
                    }
                }
                //NOTE: idea taken from https://github.com/dalek-cryptography/curve25519-dalek/pull/297/files
                use serde::ser::SerializeTuple;
                let $self = &self;
                let bytes = $block;
                let mut tup = serializer.serialize_tuple($len)?;
                for byte in bytes.iter() {
                    tup.serialize_element(byte)?;
                }
                tup.end()
            }
        }
    }
}

#[macro_export]
#[doc(hidden)]
macro_rules! impl_display_debug_serialize {
    ($($tt:tt)+) => {
        $crate::impl_serialize!($($tt)+);
        $crate::impl_display_debug!($($tt)+);
    };
}

/// Implements Display, FromStr, Serialize and Deserialize for something that
/// can be represented as a fixed length byte array
#[macro_export]
#[cfg_attr(rustfmt, rustfmt::skip)]
#[doc(hidden)]
macro_rules! impl_fromstr_deserailize {
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
                    let result = $block;
                    result.ok_or($crate::hex::HexError::InvalidEncoding)
                }
            }
        }



        #[cfg(feature = "serialization")]
        impl<'de, $($($tpl $(: $tcl)?),*)?> serde::Deserialize<'de> for $type  {
            fn deserialize<Deser: serde::Deserializer<'de>>(
                deserializer: Deser,
            ) -> Result<$type , Deser::Error> {
                #[cfg(any(feature = "serialize_hex", test))]
                {
                    if deserializer.is_human_readable() {
                        #[allow(unused_parens)]
                        struct HexVisitor$(<$($tpl),*>)?$((core::marker::PhantomData<($($tpl),*)> ))?;
                        impl<'de, $($($tpl $(: $tcl)?),*)?> serde::de::Visitor<'de> for HexVisitor$(<$($tpl),*>)? {
                            type Value = $type ;
                            fn expecting(
                                &self,
                                f: &mut core::fmt::Formatter,
                            ) -> core::fmt::Result {
                                write!(f, "a {}-byte hex encoded {}", $len, $name)?;
                                Ok(())
                            }

                            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<$type , E> {
                                use $crate::hex::HexError::*;
                                <$type  as core::str::FromStr>::from_str(v).map_err(|e| match e {
                                    InvalidLength => E::invalid_length(v.len(), &format!("{}", $len).as_str()),
                                    InvalidEncoding => E::invalid_value(serde::de::Unexpected::Str(v), &self),
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

                    impl<'de, $($($tpl $(: $tcl)?),*)?> serde::de::Visitor<'de> for BytesVisitor$(<$($tpl),*>)? {
                        type Value = $type ;

                        fn expecting(
                            &self,
                            f: &mut core::fmt::Formatter,
                        ) -> core::fmt::Result {
                            write!(f, "a valid {}-byte encoding of a {}", $len, $name)?;
                            Ok(())
                        }

                        fn visit_seq<A>(self, mut seq: A) -> Result<$type , A::Error>
                        where A: serde::de::SeqAccess<'de> {

                            let mut $input = [0u8; $len];
                            for i in 0..$len {
                                $input[i] = seq.next_element()?
                                    .ok_or_else(|| serde::de::Error::custom(format_args!("invalid length {}, expected {}", i, &self as &dyn serde::de::Expected)))?;
                            }

                            let result = $block;
                            result.ok_or(serde::de::Error::custom(format_args!("invalid byte encoding, expected {}", &self as &dyn serde::de::Expected)))
                        }
                    }

                    #[allow(unused_parens)]
                    deserializer.deserialize_tuple($len, BytesVisitor$((core::marker::PhantomData::<($($tpl),*)>))?)
                }
            }
        }

    };
}
