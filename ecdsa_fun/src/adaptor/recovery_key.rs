use secp256kfun::{Scalar,Point};
pub struct RecoveryKey<S> {
    s_hat: Scalar<S>,
    point: Point<Normal,S>,
}

s_tag = r + cx;
s = y + r + cx;

s = r_1 + H(R_1 || X_1 || m_1)*x;
