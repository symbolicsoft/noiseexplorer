/*
IK1:
  <- s
  ...
  -> e, s
  <- e, ee, se, es
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

pub mod consts;
pub mod error;
pub mod noisesession;
pub mod types;