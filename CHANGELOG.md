## Noise Explorer 0.3 (???)
- Now based on Noise Protocol Framework revision 34.
- Added deferred patterns from revision 34 to compendium (except for IK1 and KK1), with formal verification results.
- ProVerif models for PSK-using Noise Handshake Patterns now are generated with the same queries and events as non-PSK Noise Handshake Patterns.
- Redundancy elimination during the derivation phase is now enabled in ProVerif, which should speed up verification performance in some cases.
- Bug fix: command-line interface always required that attacker be specified when parsing patterns, even though the value is optional with a default value of `active`.
- Minor bug fixes.

## Noise Explorer 0.2 (May 22, 2018)
- Initial public release.