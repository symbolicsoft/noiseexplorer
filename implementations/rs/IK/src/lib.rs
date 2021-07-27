/*
IK:
  <- s
  ...
  -> e, es, s, ss
  <- e, ee, se
  ->
  <-
*/

/* ---------------------------------------------------------------- *
 * PARAMETERS                                                       *
 * ---------------------------------------------------------------- */

#[macro_use]
pub(crate) mod macros;

pub(crate) mod prims;
pub(crate) mod state;
pub(crate) mod utils;

pub mod consts;
pub mod error;
pub mod noisesession;
pub mod types;