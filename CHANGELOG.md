## Noise Explorer v1.0.2
- Noise Explorer:
	- _fix(ide): Fixed race conditions in Noise Explorer Web IDE_.
	- _fix(): Minor bug fixes_.
	
- Go:
	- _fix(go): Noise Handshake Patterns not explicitly containing post-handshake message will still generate functional Go implementations_.
	- _fix(go): Update Go implementation test suite to work with latest version of Go_.

- Rust:
	- _fix(rust): Noise Handshake Patterns not explicitly containing post-handshake message will still generate functional Rust implementations_.
	- _fix(rust): Remove deprecated usage of `description` function_.

- WebAssembly:
	- _fix(wasm): Noise Handshake Patterns not explicitly containing post-handshake message will still generate functional WASM implementations_.
## Noise Explorer v1.0.1
- Rust:
	- _fix(rust): Removed the ability to clone traits (#37)_.

- WebAssembly:
	- _fix(wasm): Removed the ability to clone traits (#37)_.
## Noise Explorer v1.0.0
- Miscelaneous:
	- _Added initial automation scripts._
	- _Added Rust testing pipeline._
	- _Reorganized generated Go tests and made minor changes to ``make tests`._
	- _Generated new implementations._
	- _Updated Travis-CI config. All implementations are passing tests in the pipeline.._
	- _Implementation versions now depend on src/versions.json._
	- _Updated pipeline script and added commit formatting._
	- _Generated new implementations._
	- _Fixed README.md for WASM implementations._
	- _Added script for automated changelog messages and version increments._
## Noise Explorer 0.3
	- Now based on Noise Protocol Framework revision 34.
	- Generate Go implementations and test-injected implementations.
	- Added detailed analysis feature for individual message patterns within Noise Handshake Patterns.
	- Added deferred handshake patterns from revision 34 to the compendium with formal verification results.
	- Added one-way handshake patterns to the compendium with formal verification results.
	- All formal verification results in the compendium, except for one-way handshake patterns, now include two tokenless message patterns.
	- The compendium now includes a search function that allows searching for Noise Handshake Pattern results by pattern name.
	- Added two parsing checks for Noise Handshake Patterns, suggested by Katriel Cohn-Gordon: `dhWithUnknownKey` and `unusedKeySent`.
	- ProVerif models for PSK-using Noise Handshake Patterns now are generated with the same queries and events as non-PSK Noise Handshake Patterns.
	- ProVerif models now generate fresh ephemerals for each session.
	- ProVerif models now have stronger separation between the sessions executed within an unbounded session model.
	- ProVerif models now model for an unbounded number of "tokenless" messages within each session in an unbounded number of sessions.
	- Redundancy elimination during the derivation phase is now enabled in ProVerif, which should speed up verification performance in some cases.
	- Bug fix: the PSK parsing check was not sufficiently precise due to a programming error.
	- Bug fix: command-line interface always required that attacker be specified when parsing patterns, even though the value is optional with a default value of `active`.
	- Add Noise Handshake Pattern validation rule 7.3.4 from revision 34.
	- ProVerif models may now be generated and downloaded directly from each Noise Handshake Pattern's compendium page.
	- Numerous other additions, improvements and bug fixes.

## Noise Explorer 0.2
	- Initial public release.