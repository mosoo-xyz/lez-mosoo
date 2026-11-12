//! LEZ v0.3.1 binary entrypoint for `mosoo_lc`.

fn main() {
    lee_core::program::run_program::<_, _, [u8], Vec<u8>>(mosoo_lez_v03::plan, mosoo_lez_v03::apply)
}
