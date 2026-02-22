# Security Policy

## Scope

Noise Explorer is a formal verification tool and code generator for the Noise Protocol Framework. Security-relevant areas include:

- **Parser (`src/parser/noiseParser.pegjs`):** Parses `.noise` pattern files. Malformed input could trigger unexpected behavior in the PEG parser.
- **Code generation (`noise2Go.js`, `noise2Rs.js`, `noise2Wasm.js`):** Template-based code generators that produce cryptographic implementations. Bugs here could result in incorrect or insecure generated code.
- **ProVerif model generation (`noise2Pv.js`):** Generates formal verification models. Errors could cause security properties to be incorrectly verified.
- **Generated implementations (`implementations/`):** Go, Rust, and WebAssembly implementations of Noise handshake patterns.
- **Web interface (`--web` mode):** Local HTTP server for the interactive explorer.

## Reporting a Vulnerability

If you discover a security vulnerability in Noise Explorer, you are welcome to report it however you prefer. Coordinated or responsible disclosure is appreciated but not required. Choose whichever channel works best for you:

- **Public issue or pull request:** Open a [GitHub issue](https://github.com/symbolicsoft/noiseexplorer/issues) or submit a pull request with a fix. This is perfectly fine and gets the community involved sooner.
- **Private advisory:** Open a [private security advisory](https://github.com/symbolicsoft/noiseexplorer/security/advisories/new) on GitHub if you prefer to discuss the issue confidentially before it is made public.
- **Email:** Send a report to the maintainers via the contact information on [symbolic.software](https://symbolic.software).

Please include:

- A description of the vulnerability and its potential impact.
- Steps to reproduce the issue or a proof of concept.
- The affected component (parser, code generator, generated implementation, etc.).
- The version or commit hash you tested against.

We will acknowledge receipt within 7 days and aim to provide a fix or mitigation plan within 30 days, depending on severity.

## Supported Versions

Security fixes are applied to the latest release on the `master` branch. There is no backporting to older versions.

| Version | Supported |
|---------|-----------|
| Latest  | Yes       |
| Older   | No        |

## Security Considerations for Users

- **Generated code is only as correct as the generator.** Always run the ProVerif formal verification step (`make models`) and review its output before trusting a generated implementation in production.
- **Pin your dependencies.** If you use generated Go or Rust code, pin the cryptographic library versions specified in the generated `go.mod` or `Cargo.toml` files.
- **Do not edit generated files directly.** Fixes should be made in the source templates (`src/go/`, `src/rs/`, `src/wasm/`) or the parser grammar (`src/parser/noiseParser.pegjs`), then regenerated.
