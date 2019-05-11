/*
XKpsk3:
  <- s
  ...
  -> e, es
  <- e, ee
  -> s, se, psk
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
