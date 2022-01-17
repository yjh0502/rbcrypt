use rustler::types::Binary;
use rustler::Error::BadArg;
use rustler::{Encoder, Env, NifResult, Term};

mod atoms {
    rustler::atoms! {
        ok,
        t = "true",
        f = "false",

        internal,
    }
}

rustler::init!("rbcrypt", [nif_hash, nif_verify]);

#[rustler::nif]
fn nif_hash<'a>(env: Env<'a>, pw: Term<'a>, cost: u32) -> NifResult<Term<'a>> {
    let pw = Binary::from_term(pw)?;

    match bcrypt::hash(pw.as_slice(), cost) {
        Ok(res) => Ok((atoms::ok(), res).encode(env)),
        Err(_e) => Err(rustler::Error::Atom("internal")),
    }
}

#[rustler::nif]
fn nif_verify<'a>(env: Env<'a>, pw: Term<'a>, hash: Term<'a>) -> NifResult<Term<'a>> {
    let pw = Binary::from_term(pw)?;
    let hash = Binary::from_term(hash)?;
    let hash_str = std::str::from_utf8(&hash).map_err(|_e| BadArg)?;

    match bcrypt::verify(pw.as_slice(), hash_str) {
        Ok(res) => Ok((atoms::ok(), res).encode(env)),
        Err(_e) => Err(rustler::Error::Atom("internal")),
    }
}
