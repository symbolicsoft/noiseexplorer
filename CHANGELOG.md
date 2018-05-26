## Noise Explorer 0.3 (???)
- Now based on Noise Protocol Framework revision 34.
- Added deferred handshake patterns from revision 34 to the compendium with formal verification results.
- Added one-way handshake patterns to the compendium with formal verification results.
- All formal verification results in the compendium, except for one-way handshake patterns, now include two tokenless message patterns.
- The compendium now includes a search function that allows searching for Noise Handshake Pattern results by pattern name.
- Added two parsing checks for Noise Handshake Patterns, suggested by Katriel Cohn-Gordon: `dhWithUnknownKey` and `unusedKeySent`.
- ProVerif models for PSK-using Noise Handshake Patterns now are generated with the same queries and events as non-PSK Noise Handshake Patterns.
- The `RecvEnd` query has been removed from ProVerif models, as it is no longer useful at this stage and slows down verification times.
- Redundancy elimination during the derivation phase is now enabled in ProVerif, which should speed up verification performance in some cases.
- Bug fix: the PSK parsing check was not sufficiently precise due to a programming error.
- Bug fix: command-line interface always required that attacker be specified when parsing patterns, even though the value is optional with a default value of `active`.
- Minor bug fixes.

## Noise Explorer 0.2 (May 22, 2018)
- Initial public release.