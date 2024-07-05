#![allow(unused)]
use super::Input;
use proc_macro2::{token_stream, Delimiter, Punct, Span, TokenStream, TokenTree};
use quote::{quote_spanned, ToTokens};
use std::{fmt::Display, iter::Peekable};

#[derive(Clone)]
pub(crate) enum OpTree {
    Infix(Infix),
    Term(TokenStream),
    Paren(Node),
    Unary(Unary),
    LitInt(u32),
}

#[derive(Clone)]
pub(crate) struct Node {
    pub tree: Box<OpTree>,
    pub span: Span,
}

impl core::fmt::Debug for Node {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.tree.fmt(f)
    }
}

impl core::fmt::Debug for OpTree {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Infix(infix) => f
                .debug_tuple(&infix.kind.to_string())
                .field(&infix.lhs)
                .field(&infix.rhs)
                .finish(),
            Self::Term(arg0) => write!(f, "{}", arg0.to_string().replace(' ', "")),
            Self::Paren(arg0) => arg0.fmt(f),
            Self::Unary(unary) => f
                .debug_tuple(&unary.kind.to_string())
                .field(&unary.subj)
                .finish(),
            Self::LitInt(arg0) => write!(f, "{}", arg0),
        }
    }
}

impl Node {
    fn new(tree: OpTree, span: Span) -> Self {
        Node {
            tree: Box::new(tree),
            span,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Infix {
    pub lhs: Node,
    pub rhs: Node,
    pub kind: InfixKind,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum InfixKind {
    Add,
    Mul,
    Sub,
    LinComb,
    Div,
}

impl InfixKind {
    fn precedence(self) -> u8 {
        match self {
            InfixKind::Add | InfixKind::Sub => 0,
            InfixKind::Mul | InfixKind::LinComb | InfixKind::Div => 1,
        }
    }
}

impl core::fmt::Display for InfixKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", match self {
            InfixKind::Add => "+",
            InfixKind::Mul => "*",
            InfixKind::Sub => "-",
            InfixKind::LinComb => ".*",
            InfixKind::Div => "/",
        })
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Unary {
    pub subj: Node,
    pub kind: UnaryKind,
    pub punct: Punct,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum UnaryKind {
    Neg,
    Ref,
}

impl core::fmt::Display for UnaryKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", match self {
            UnaryKind::Neg => "-",
            UnaryKind::Ref => "&",
        })
    }
}

#[derive(Clone, Debug)]
pub struct Error {
    pub span: Span,
    pub problem: String,
}

pub(crate) fn token_stream_to_node(ts: token_stream::TokenStream) -> Result<Node, Error> {
    parse_tokens(&mut ts.into_iter().peekable())
}

pub(crate) fn parse_tokens(input: &mut Input) -> Result<Node, Error> {
    rule_opchain(input)
}

fn rule_term(input: &mut Input) -> Result<Node, Error> {
    let unaries = rule_prefix(input)?;
    let next = input
        .peek()
        .expect("must not be called with an empty input");
    let mut span = next.span();
    let mut optree = match next {
        TokenTree::Ident(_) => {
            let mut tt = TokenStream::new();
            tt.extend(input.next());
            tt.extend(rule_postfix(input)?);
            OpTree::Term(tt)
        }
        TokenTree::Group(group) => {
            let group = group.clone();
            match group.delimiter() {
                Delimiter::Parenthesis => {
                    let _ = input.next();
                    OpTree::Paren(token_stream_to_node(group.stream())?)
                }
                Delimiter::Brace => {
                    let input: TokenStream = input.next().unwrap().into();
                    let term = quote_spanned! { span => #[allow(unused_braces)] #input };
                    OpTree::Term(term)
                }
                _ => {
                    return Err(Error {
                        span: group.span(),
                        problem: "can only use '(..)' or '{..}'".into(),
                    })
                }
            }
        }
        TokenTree::Literal(lit) => {
            let int_lit: u32 = lit.to_string().parse().map_err(|e| Error {
                span: lit.span(),
                problem: "only u32 literals are supported".into(),
            })?;
            let _ = input.next();
            OpTree::LitInt(int_lit)
        }
        tt => {
            return Err(Error {
                span: tt.span(),
                problem: "this is an invalid term".into(),
            })
        }
    };

    for (unary_kind, punct) in unaries {
        optree = OpTree::Unary(Unary {
            kind: unary_kind,
            subj: Node::new(optree, span),
            punct: punct.clone(),
        });
        span = punct.span();
    }
    Ok(Node::new(optree, span))
}

fn rule_prefix(input: &mut Input) -> Result<Vec<(UnaryKind, Punct)>, Error> {
    let mut unaries = vec![];
    while let Some(TokenTree::Punct(punct)) = input.peek() {
        match punct.as_char() {
            '-' => {
                unaries.push((UnaryKind::Neg, punct.to_owned()));
                let _ = input.next();
            }
            '&' => {
                unaries.push((UnaryKind::Ref, punct.to_owned()));
                let _ = input.next();
            }
            _ => break,
        }
    }
    Ok(unaries)
}
fn rule_postfix(input: &mut Input) -> Result<Vec<TokenTree>, Error> {
    let mut tokens = vec![];

    loop {
        let mut lookahead = input.clone();
        let next = lookahead.next();
        match next {
            Some(TokenTree::Punct(punct)) => {
                if punct.as_char() == '.' {
                    let is_dot_product = matches!(lookahead.peek(), Some(TokenTree::Punct(punct)) if punct.as_char() == '*');
                    if is_dot_product {
                        break;
                    }

                    tokens.push(input.next().unwrap());

                    let error = Err(Error {
                        span: punct.span(),
                        problem:
                            "expecting a method call, property access or tuple access after period"
                                .into(),
                    });
                    // look for .0, .foo or .foo(a,b)
                    match input.next() {
                        Some(following_period) => match &following_period {
                            TokenTree::Ident(_) => {
                                tokens.push(following_period);
                            }
                            TokenTree::Literal(lit) if lit.to_string().parse::<f32>().is_ok() => {
                                tokens.push(following_period);
                            }
                            _following_period => return error,
                        },
                        None => return error,
                    }
                } else {
                    break;
                }
            }
            Some(TokenTree::Group(group)) if group.delimiter() == Delimiter::Parenthesis => {
                tokens.push(input.next().unwrap());
            }
            Some(TokenTree::Group(group)) if group.delimiter() == Delimiter::Bracket => {
                tokens.push(input.next().unwrap());
            }
            _ => break,
        }
    }

    Ok(tokens)
}

fn rule_opchain(input: &mut Input) -> Result<Node, Error> {
    let mut lhs = rule_term(input)?;

    if input.peek().is_none() {
        return Ok(lhs);
    }

    let (kind, span) = rule_infix_op(input)?;

    let mut rhs = rule_opchain(input)?;
    let mut top_node = Node::new(OpTree::Infix(Infix { lhs, rhs, kind }), span);
    let mut cursor = &mut top_node;

    while let OpTree::Infix(infix) = &*cursor.tree {
        match &*infix.rhs.tree {
            OpTree::Infix(rhs_infix) if infix.kind.precedence() >= rhs_infix.kind.precedence() => {
                let fixed = Node::new(
                    OpTree::Infix(Infix {
                        lhs: Node::new(
                            OpTree::Infix(Infix {
                                lhs: infix.lhs.clone(),
                                rhs: rhs_infix.lhs.clone(),
                                kind,
                            }),
                            span,
                        ),
                        rhs: rhs_infix.rhs.clone(),
                        kind: rhs_infix.kind,
                    }),
                    infix.rhs.span,
                );
                *cursor = fixed;
                cursor = match &mut *cursor.tree {
                    OpTree::Infix(infix) => &mut infix.lhs,
                    _ => unreachable!(),
                }
            }
            _ => break,
        }
    }

    Ok(top_node)
}

fn rule_infix_op(input: &mut Input) -> Result<(InfixKind, Span), Error> {
    let next = input.next().expect("must not be called on empty input");
    match next {
        TokenTree::Punct(punct) => {
            let error = Err(Error {
                span: punct.span(),
                problem: "unknown infix operator".into(),
            });

            let op = match punct.as_char() {
                '+' => InfixKind::Add,
                '*' => InfixKind::Mul,
                '-' => InfixKind::Sub,
                '.' => match input.next() {
                    Some(TokenTree::Punct(star)) if star.as_char() == '*' => InfixKind::LinComb,
                    _ => return error,
                },
                '/' => InfixKind::Div,
                _ => return error,
            };
            Ok((op, punct.span()))
        }
        _ => Err(Error {
            span: next.span(),
            problem: "expecting an infix operator".into(),
        }),
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::str::FromStr;

    macro_rules! parse {
        ($lit:expr) => {
            *match token_stream_to_node(TokenStream::from_str($lit).unwrap()) {
                Err(e) => panic!("{}", e.problem),
                Ok(expr) => expr,
            }
            .tree
        };
    }

    #[test]
    fn test_term() {
        assert!(matches!(parse!("a_term"), OpTree::Term(tt) if tt.to_string() == "a_term"));
    }

    #[test]
    fn add2() {
        let ot = parse!("a + b");
        assert!(
            matches!(ot, OpTree::Infix (Infix {  lhs, rhs, kind: InfixKind::Add  }) if
                    matches!(&*lhs.tree, OpTree::Term(tt) if tt.to_string() == "a") &&
                    matches!(&*rhs.tree, OpTree::Term(tt) if tt.to_string() == "b")
            )
        );
    }

    #[test]
    fn add3() {
        let ot = parse!("a + b + c");
        assert!(
            matches!(ot, OpTree::Infix(Infix { lhs, rhs, kind: InfixKind::Add }) if
                             matches!(&*lhs.tree, OpTree::Infix(Infix{ lhs, rhs, kind: InfixKind::Add }) if
                                      matches!(&*lhs.tree, OpTree::Term(a) if a.to_string() == "a") &&
                                      matches!(&*rhs.tree, OpTree::Term(b) if b.to_string() == "b")
                             )  &&
                    matches!(&*rhs.tree, OpTree::Term(c) if c.to_string() == "c")
            )
        );
    }

    #[test]
    fn add_mul3() {
        let ot = parse!("a * A + b * B + c * C");
        assert!(
            matches!(ot, OpTree::Infix(Infix { lhs, rhs, kind: InfixKind::Add }) if
                matches!(&*lhs.tree, OpTree::Infix(Infix { lhs, rhs, kind: InfixKind::Add })
                    if matches!(&*lhs.tree, OpTree::Infix(Infix { lhs, rhs, kind: InfixKind::Mul })) &&
                        matches!(&*rhs.tree, OpTree::Infix(Infix { lhs, rhs, kind: InfixKind::Mul }))
                ) &&
                matches!(&*rhs.tree, OpTree::Infix(Infix { lhs, rhs, kind: InfixKind::Mul })))
        );
    }

    #[test]
    fn addparen() {
        let ot = parse!("(a + b) + c");
        assert!(
            matches!(ot, OpTree::Infix(Infix { lhs, kind: InfixKind::Add, .. }) if
            matches!(&*lhs.tree, OpTree::Paren(paren) if
                     matches!(&*paren.tree, OpTree::Infix(Infix { kind: InfixKind::Add, .. }))
            ))
        );
    }

    #[test]
    fn addparen2() {
        let ot = parse!("a + (b + c)");
        assert!(
            matches!(ot, OpTree::Infix(Infix { rhs, kind: InfixKind::Add, .. }) if
            matches!(&*rhs.tree, OpTree::Paren(paren) if
                     matches!(&*paren.tree, OpTree::Infix(Infix { kind: InfixKind::Add, .. }))
            ))
        );
    }

    #[test]
    fn addmul() {
        let ot = parse!("a + b * c");
        assert!(
            matches!(ot, OpTree::Infix(Infix { lhs, rhs, kind: InfixKind::Add }) if
                             matches!(&*lhs.tree, OpTree::Term(a) if a.to_string() == "a")
                               &&
                             matches!(&*rhs.tree, OpTree::Infix(Infix{ lhs, rhs, kind: InfixKind::Mul }) if
                                      matches!(&*lhs.tree, OpTree::Term(b) if b.to_string() == "b") &&
                                      matches!(&*rhs.tree, OpTree::Term(c) if c.to_string() == "c")
                             )
            )
        );
    }

    #[test]
    fn muladd() {
        let ot = parse!("a * b + c");
        assert!(
            matches!(ot, OpTree::Infix(Infix { lhs, rhs, kind: InfixKind::Add }) if
                             matches!(&*lhs.tree, OpTree::Infix(Infix{ lhs, rhs, kind: InfixKind::Mul }) if
                                      matches!(&*lhs.tree, OpTree::Term(a) if a.to_string() == "a") &&
                                      matches!(&*rhs.tree, OpTree::Term(b) if b.to_string() == "b")
                             )  &&
                    matches!(&*rhs.tree, OpTree::Term(c) if c.to_string() == "c")
            )
        );
    }

    #[test]
    fn addsub() {
        let ot = parse!("a + b - c");
        assert!(
            matches!(ot, OpTree::Infix(Infix { lhs, rhs, kind: InfixKind::Sub }) if
                             matches!(&*lhs.tree, OpTree::Infix(Infix{ lhs, rhs, kind: InfixKind::Add }) if
                                      matches!(&*lhs.tree, OpTree::Term(a) if a.to_string() == "a") &&
                                      matches!(&*rhs.tree, OpTree::Term(b) if b.to_string() == "b")
                             )  &&
                    matches!(&*rhs.tree, OpTree::Term(c) if c.to_string() == "c")
            )
        );
    }

    #[test]
    fn subadd() {
        let ot = parse!("a - b + c");
        assert!(
            matches!(ot, OpTree::Infix(Infix { lhs, rhs, kind: InfixKind::Add }) if
                             matches!(&*lhs.tree, OpTree::Infix(Infix{ lhs, rhs, kind: InfixKind::Sub }) if
                                      matches!(&*lhs.tree, OpTree::Term(a) if a.to_string() == "a") &&
                                      matches!(&*rhs.tree, OpTree::Term(b) if b.to_string() == "b")
                             )  &&
                    matches!(&*rhs.tree, OpTree::Term(c) if c.to_string() == "c")
            )
        );
    }

    #[test]
    fn unary_negate() {
        let ot = parse!("-a");
        assert!(
            matches!(ot, OpTree::Unary(Unary { kind: UnaryKind::Neg, subj, .. }) if matches!(&*subj.tree, OpTree::Term(a) if a.to_string() == "a"))
        )
    }

    #[test]
    fn unary_ref() {
        let ot = parse!("&a");
        assert!(
            matches!(ot, OpTree::Unary(Unary { kind: UnaryKind::Ref, subj, .. }) if matches!(&*subj.tree, OpTree::Term(a) if a.to_string() == "a"))
        )
    }

    #[test]
    fn double_negate() {
        let ot = parse!("--a");
        assert!(
            matches!(ot, OpTree::Unary(Unary { kind: UnaryKind::Neg, subj, ..})
                     if matches!(&*subj.tree, OpTree::Unary(Unary { kind: UnaryKind::Neg, subj, .. })
                                 if matches!(&*subj.tree, OpTree::Term(a) if a.to_string() == "a")))
        )
    }

    #[test]
    fn unary_negate_with_infix() {
        let ot = parse!("-a * b");
        assert!(matches!(ot, OpTree::Infix( Infix { lhs, .. },)
                     if   matches!(&*lhs.tree, OpTree::Unary(Unary { kind: UnaryKind::Neg, subj, .. })
                                   if matches!(&*subj.tree, OpTree::Term(a) if a.to_string() == "a"))))
    }

    #[test]
    fn dot_product() {
        let ot = parse!("a .* b");
        assert!(
            matches!(ot, OpTree::Infix( Infix { lhs, rhs, kind: InfixKind::LinComb } ) if
                             matches!(&*lhs.tree, OpTree::Term(a) if a.to_string() == "a") &&
                             matches!(&*rhs.tree, OpTree::Term(b) if b.to_string() == "b")
            )
        )
    }

    #[test]
    fn callmethod() {
        let ot = parse!("term.method(other, stuff)");
        assert!(
            matches!(ot, OpTree::Term(call) if call.to_string() == "term . method (other , stuff)")
        );
        let ot = parse!("term.method(other, stuff).another()");
        assert!(
            matches!(ot, OpTree::Term(call) if call.to_string() == "term . method (other , stuff) . another ()")
        );
    }

    #[test]
    fn property() {
        let ot = parse!("term.property");
        assert!(matches!(ot, OpTree::Term(call) if call.to_string() == "term . property"));
        let ot = parse!("term.property.another");
        assert!(
            matches!(ot, OpTree::Term(call) if call.to_string() == "term . property . another")
        );
    }

    #[test]
    fn tuple_index() {
        let ot = parse!("term.0");
        assert!(matches!(ot, OpTree::Term(call) if call.to_string().replace(' ', "") == "term.0"));
        let ot = parse!("term.1.2.3");
        assert!(
            matches!(ot, OpTree::Term(call) if call.to_string().replace(' ', "") == "term.1.2.3")
        );
    }

    #[test]
    fn array_index() {
        let ot = parse!("term[1]");
        assert!(matches!(ot, OpTree::Term(call) if call.to_string().replace(' ', "") == "term[1]"));
        let ot = parse!("term[1..10]");
        assert!(
            matches!(ot, OpTree::Term(call) if call.to_string().replace(' ', "") == "term[1..10]")
        );
    }

    #[test]
    fn lots_of_junk_added() {
        let ot = parse!("term(arg1, arg2)[1].7.a_method()[2] + what.a.long.1[6].tail(of, things)");
        assert!(
            matches!(ot, OpTree::Infix( Infix { lhs, rhs, kind: InfixKind::Add }) if
                     matches!(&*lhs.tree, OpTree::Term(call) if call.to_string().replace(' ', "") == "term(arg1,arg2)[1].7.a_method()[2]") &&
                     matches!(&*rhs.tree, OpTree::Term(call) if call.to_string().replace(' ', "") == "what.a.long.1[6].tail(of,things)"))
        );
    }

    #[test]
    fn int_lit() {
        let ot = parse!("1");
        assert!(matches!(ot, OpTree::LitInt(1u32)));
    }
}
