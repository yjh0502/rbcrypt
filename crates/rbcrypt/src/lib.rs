#[macro_use]
extern crate rustler;

use rustler::schedule::SchedulerFlags;
use rustler::types::Binary;
use rustler::Error::BadArg;
use rustler::{Encoder, Env, NifResult, Term};

mod atoms {
    rustler_atoms! {
        atom ok;
        atom t = "true";
        atom f = "false";

        atom internal;
    }
}

rustler_export_nifs!(
    "rbcrypt",
    [
        ("nif_hash", 2, hash, SchedulerFlags::DirtyCpu),
        ("nif_verify", 2, verify, SchedulerFlags::DirtyCpu)
    ],
    None
);

fn hash<'a>(env: Env<'a>, args: &[Term<'a>]) -> NifResult<Term<'a>> {
    if args.len() != 2 {
        return Err(BadArg);
    }

    let pw = Binary::from_term(args[0])?;
    let cost = args[1].decode::<u32>()?;

    match bcrypt::hash(pw.as_slice(), cost) {
        Ok(res) => Ok((atoms::ok(), res).encode(env)),
        Err(_e) => Err(rustler::Error::Atom("internal")),
    }
}

fn verify<'a>(env: Env<'a>, args: &[Term<'a>]) -> NifResult<Term<'a>> {
    if args.len() != 2 {
        return Err(BadArg);
    }

    let pw = Binary::from_term(args[0])?;
    let hash = Binary::from_term(args[1])?;
    let hash_str = std::str::from_utf8(&hash).map_err(|_e| BadArg)?;

    match bcrypt::verify(pw.as_slice(), hash_str) {
        Ok(res) => Ok((atoms::ok(), res).encode(env)),
        Err(_e) => Err(rustler::Error::Atom("internal")),
    }
}
