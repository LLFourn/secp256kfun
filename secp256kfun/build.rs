#![allow(non_snake_case)]
use secp256kfun_parity_backend::{
    ecmult::{ECMultContext, ECMultGenContext},
    group::AffineStorage,
};
use std::{
    env,
    fs::File,
    io::{self, Write},
    path::Path,
};

fn main() {
    // scratch: v0.1.2
    println!("cargo:rerun-if-changed=build.rs");
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let ecmult_path = Path::new(&out_dir).join("ecmult_table.rs");
    let mut ecmult_file = File::create(&ecmult_path).expect("Create ecmult_table.rs file failed");
    write_ecmult_table(&mut ecmult_file).expect("Write ecmult_table.rs file failed");
    ecmult_file
        .flush()
        .expect("Flush ecmult_table.rs file failed");
    let ecmult_gen_path = Path::new(&out_dir).join("ecmult_gen_table.rs");
    let mut ecmult_gen_file =
        File::create(&ecmult_gen_path).expect("Create ecmult_gen_table.rs file failed");
    write_ecmult_gen_table(&mut ecmult_gen_file).expect("Write ecmult_gen_table.rs file failed");
    ecmult_gen_file
        .flush()
        .expect("Flush ecmult_gen_table.rs file failed");
}

fn write_ecmult_gen_table(file: &mut File) -> Result<(), io::Error> {
    let context = ECMultGenContext::new_boxed();
    let prec = context.inspect_raw().as_ref();

    file.write_fmt(format_args!("["))?;
    for j in 0..64 {
        file.write_fmt(format_args!("    ["))?;
        for i in 0..16 {
            let pg: AffineStorage = prec[j][i].clone().into();
            file.write_fmt(format_args!(
                "        secp256kfun_parity_backend::group::AffineStorage::new(secp256kfun_parity_backend::field::FieldStorage::new({}, {}, {}, {}, {}, {}, {}, {}), secp256kfun_parity_backend::field::FieldStorage::new({}, {}, {}, {}, {}, {}, {}, {})),",
                pg.x.0[7], pg.x.0[6], pg.x.0[5], pg.x.0[4], pg.x.0[3], pg.x.0[2], pg.x.0[1], pg.x.0[0],
                pg.y.0[7], pg.y.0[6], pg.y.0[5], pg.y.0[4], pg.y.0[3], pg.y.0[2], pg.y.0[1], pg.y.0[0]
            ))?;
        }
        file.write_fmt(format_args!("    ],"))?;
    }
    file.write_fmt(format_args!("]"))?;

    Ok(())
}

fn write_ecmult_table(file: &mut File) -> Result<(), io::Error> {
    let context = ECMultContext::new_boxed();
    let pre_g = context.inspect_raw().as_ref();

    file.write_fmt(format_args!("["))?;
    for pg in pre_g {
        file.write_fmt(
            format_args!(
                "    secp256kfun_parity_backend::group::AffineStorage::new(secp256kfun_parity_backend::field::FieldStorage::new({}, {}, {}, {}, {}, {}, {}, {}), secp256kfun_parity_backend::field::FieldStorage::new({}, {}, {}, {}, {}, {}, {}, {})),",
                pg.x.0[7], pg.x.0[6], pg.x.0[5], pg.x.0[4], pg.x.0[3], pg.x.0[2], pg.x.0[1], pg.x.0[0],
                pg.y.0[7], pg.y.0[6], pg.y.0[5], pg.y.0[4], pg.y.0[3], pg.y.0[2], pg.y.0[1], pg.y.0[0]
            )
        )?;
    }
    file.write_fmt(format_args!("]"))?;

    Ok(())
}
