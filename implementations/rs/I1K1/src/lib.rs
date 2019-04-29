/*
I1K1:
  <- s
  ...
  -> e, s
  <- e, ee, es
  -> se
  <-
  ->
*/

/* ---------------------------------------------------------------- *
 * PARAMETERS                                                       *
 * ---------------------------------------------------------------- */

#[macro_use]
pub(crate) mod macros;

pub(crate) mod consts;
pub(crate) mod prims;
pub(crate) mod state;

pub mod error;
pub mod noisesession;
pub mod types;