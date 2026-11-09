use secp256kfun::{
    G, Point, g,
    marker::{Normal, Secret, Zero},
};

#[test]
fn normalized_secret_equality_handles_identity_and_opposites() {
    let identity = Point::<Normal, Secret, Zero>::zero();
    let point = G.normalize().secret().mark_zero();
    let cancelled = g!(point - point).normalize().secret();

    for zero in [identity, cancelled] {
        assert_eq!(zero, identity);
        assert_eq!(identity, zero);
        assert_ne!(zero, point);
        assert_ne!(point, zero);
    }
    assert_eq!(point, point);
    assert_eq!(point, g!(point + identity).normalize());
    assert_ne!(point, -point);
    assert_ne!(-point, point);
    assert_ne!(point, g!(point + point).normalize());
}
