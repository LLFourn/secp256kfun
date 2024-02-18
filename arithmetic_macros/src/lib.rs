//!
#![cfg_attr(docsrs, feature(doc_cfg))]
#![allow(non_snake_case)]
#![doc = include_str!("../README.md")]
#![warn(missing_docs)]

mod optree;
use optree::{Infix, InfixKind, Node, OpTree};
use proc_macro::TokenStream;
use proc_macro2::{Ident, TokenTree};
use quote::{quote, quote_spanned};
use std::iter::Peekable;
type Input = Peekable<proc_macro2::token_stream::IntoIter>;

#[proc_macro]
/// Helper to generate the `s!` macro
pub fn gen_s(input: TokenStream) -> TokenStream {
    let input: proc_macro2::TokenStream = input.into();
    let mut iter = input.into_iter().peekable();

    let path = match iter.next() {
        Some(TokenTree::Ident(path)) => path,
        _ => panic!("put the path to secpfun crate first"),
    };
    let optree = match optree::parse_tokens(&mut iter) {
        Ok(optree) => optree,
        Err(e) => {
            let problem = e.problem;
            return quote_spanned!(e.span => compile_error!(#problem)).into();
        }
    };

    compile_s(&path, optree).into()
}

fn compile_s(path: &Ident, node: Node) -> proc_macro2::TokenStream {
    match *node.tree {
        OpTree::Infix(Infix { lhs, rhs, kind }) => {
            let lhs_ = compile_s(path, lhs);
            let mut rhs_ = compile_s(path, rhs);
            let fn_name = Ident::new(
                match kind {
                    InfixKind::Add => "scalar_add",
                    InfixKind::Mul => "scalar_mul",
                    InfixKind::Sub => "scalar_sub",
                    InfixKind::LinComb => "scalar_dot_product",
                    InfixKind::Div => {
                        rhs_ = quote_spanned! { node.span => #path::op::scalar_invert(#rhs_) };
                        "scalar_mul"
                    }
                },
                node.span,
            );

            quote_spanned! { node.span =>  #path::op::#fn_name(#lhs_, #rhs_) }
        }
        OpTree::Unary(unary) => match unary.kind {
            optree::UnaryKind::Neg => {
                let fn_name = Ident::new("scalar_negate", node.span);
                let subj = compile_s(path, unary.subj);
                quote_spanned! { node.span => #path::op::#fn_name(#subj) }
            }
            optree::UnaryKind::Ref => {
                let a = unary.punct;
                let subj = compile_g(path, unary.subj);
                quote!( #a #subj )
            }
        },
        OpTree::Term(ts) => ts,
        OpTree::Paren(node) => compile_s(path, node),
        OpTree::LitInt(lit_int) => {
            if lit_int == 0 {
                quote_spanned! { node.span =>  #path::Scalar::<#path::marker::Secret, _>::zero() }
            } else {
                quote_spanned! { node.span =>
                    #path::Scalar::<#path::marker::Secret, #path::marker::NonZero>::from_non_zero_u32(unsafe {
                        core::num::NonZeroU32::new_unchecked(#lit_int)
                    })
                }
            }
        }
    }
}

#[proc_macro]
/// Helper to generate the `g!` macro
pub fn gen_g(input: TokenStream) -> TokenStream {
    let input: proc_macro2::TokenStream = input.into();
    let mut iter = input.into_iter().peekable();

    let path = match iter.next() {
        Some(TokenTree::Ident(path)) => path,
        _ => panic!("put the path to secpfun crate first"),
    };
    let node = match optree::parse_tokens(&mut iter) {
        Ok(optree) => optree,
        Err(e) => {
            let problem = e.problem;
            return quote_spanned!(e.span => compile_error!(#problem)).into();
        }
    };

    compile_g(&path, node).into()
}

fn compile_g(path: &Ident, node: Node) -> proc_macro2::TokenStream {
    match *node.tree {
        OpTree::Infix(Infix { lhs, rhs, kind }) => match kind {
            InfixKind::Add | InfixKind::Sub => {
                let is_sub = kind == InfixKind::Sub;
                match (&*lhs.tree, &*rhs.tree) {
                    (
                        OpTree::Infix(Infix {
                            kind: InfixKind::Mul,
                            lhs: llhs,
                            rhs: lrhs,
                        }),
                        OpTree::Infix(Infix {
                            kind: InfixKind::Mul,
                            lhs: rlhs,
                            rhs: rrhs,
                        }),
                    ) => {
                        let llhs = compile_s(path, llhs.clone());
                        let lrhs = compile_g(path, lrhs.clone());
                        let mut rlhs = compile_s(path, rlhs.clone());
                        let rrhs = compile_g(path, rrhs.clone());
                        if is_sub {
                            rlhs = quote_spanned! { node.span => #path::op::scalar_negate(#rlhs) };
                        }
                        quote_spanned! { node.span => #path::op::double_mul(#llhs, #lrhs, #rlhs, #rrhs) }
                    }
                    (..) => {
                        let lhs_ = compile_g(path, lhs);
                        let rhs_ = compile_g(path, rhs);
                        if is_sub {
                            quote_spanned! { node.span => #path::op::point_sub(#lhs_, #rhs_) }
                        } else {
                            quote_spanned! { node.span => #path::op::point_add(#lhs_, #rhs_) }
                        }
                    }
                }
            }
            InfixKind::Mul => {
                let lhs_ = compile_s(path, lhs);
                let rhs_ = compile_g(path, rhs);
                quote_spanned! { node.span => #path::op::scalar_mul_point(#lhs_, #rhs_) }
            }
            InfixKind::LinComb => {
                let lhs_ = compile_s(path, lhs);
                let rhs_ = compile_g(path, rhs);
                quote_spanned! { node.span => #path::op::point_scalar_dot_product(#lhs_, #rhs_) }
            }
            InfixKind::Div => {
                quote_spanned! { node.span => compile_error!("can't use division in group expression") }
            }
        },
        OpTree::Term(term) => term,
        OpTree::Paren(node) => compile_g(path, node),
        OpTree::Unary(unary) => match unary.kind {
            optree::UnaryKind::Neg => {
                let fn_name = Ident::new("point_negate", node.span);
                let subj = compile_g(path, unary.subj);
                quote_spanned! { node.span => #path::op::#fn_name(#subj) }
            }
            optree::UnaryKind::Ref => {
                let a = unary.punct;
                let subj = compile_g(path, unary.subj);
                quote!( #a #subj )
            }
        },
        OpTree::LitInt(lit_int) => {
            quote_spanned! { node.span => compile_error!("can't use literal int {} in group expression", #lit_int)}
        }
    }
}
