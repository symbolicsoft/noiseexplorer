# [Noise Explorer](https://noiseexplorer.com)
## Version 0.3, based on Noise Protocol Revision 34.

### Overview
The Noise Explorer command-line tool can parse Noise Handshake Patterns according to the original specification. It can generate cryptographic models for formal verification, including security queries, top-level processes and malicious principals, for testing against an active or passive attacker. Noise Explorer can also generate fully functional discrete implementations for any Noise Handshake Pattern, written in the [Go](https://golang.org) and [Rust](https://www.rust-lang.org/) programming languages.

Noise Explorer can also render results from the ProVerif output into an elegant and easy to read HTML format: the pattern results that can be explored on [Noise Explorer](https://noiseexplorer.com) were generated using the Noise Explorer command-line tool.

### Status
| Output   | Functional | Reliable | Unit Tests |
|----------|------------|----------|------------|
| ProVerif | ✔️          | ✔️        | ✔️          |
| Go       | ✔️          | ✔️        | ✔️          |
| Rust     | ❌         | ❌       | ❌         |

### Usage

```
$> node noiseExplorer --help
Noise Explorer version 0.3 (specification revision 34)
Noise Explorer has three individual modes: generation, rendering and web interface.

Generation:
--generate=(json|pv|go|rs): Specify output format.
--pattern=[file]: Specify input pattern file (required).
--attacker=(active|passive): Specify ProVerif attacker type (default: active).
--testgen: Embed test vectors into the generated implementation.

Rendering:
--render=(handshake|message): Render results from ProVerif output files into HTML.
--pattern=[file]: Specify input pattern file (required).
--activeModel=[file]: Specify ProVerif active attacker model (required for --render=message).
--activeResults=[file]: Specify active results file for --render (required).
--passiveResults=[file]: Specify passive results file for --render (required).

Web interface:
--web=(port): Make Noise Explorer's web interface available at http://localhost:(port) (default: 8000).

Help:
--help: View this help text.
```

### Requirements
1. [Node](https://nodejs.org) is required for running Noise Explorer locally.
2. [ProVerif](http://prosecco.gforge.inria.fr/personal/bblanche/proverif/) is required for verifying generated models.
2. [Go](https://golang.org) and [Rust](https://www.rust-lang.org) are required for running generated implementations.

### Preparation
1. `cd src`
2. `make dependencies`
3. `make parser`

### Usage
`node noiseExplorer --help`

### Model Generation
To quickly translate all Noise handshake patterns in the `patterns` folder to ProVerif models, simply run `make models` after completing the steps outlined in the Preparation section of this document. The models will be available in the `models` folder.

### Implementation Generation
To quickly translate all Noise handshake patterns in the `patterns` folder to Go and Rust implementations, simply run `make implementations` after completing the steps outlined in the Preparation section of this document. The models will be available in the `implementations` folder. Running `make tests` will also generate test-injected implementations and verify them against test vectors obtained from [Cacophony](https://github.com/centromere/cacophony), a Haskell implementation of the Noise Protocol Framework.

### Contributors and License
Authored by [Nadim Kobeissi](https://nadim.computer) and [Georgio Nicholas](https://georgio.xyz). Released under the GNU General Public License, version 3.
