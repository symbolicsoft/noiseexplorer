# [Noise Explorer](https://noiseexplorer.com)
## Version 0.3, based on Noise Protocol Revision 34.

### Overview
The Noise Explorer command-line tool can parse Noise Handshake Patterns according to the original specification. It can generate cryptographic models for formal verification, including security queries, top-level processes and malicious principals, for testing against an active or passive attacker.

Noise Explorer can also render results from the ProVerif output into an elegant and easy to read HTML format: the pattern results that can be explored on [Noise Explorer](https://noiseexplorer.com) were generated using the Noise Explorer command-line tool.

```
$> node noiseExplorer --help
	Noise Explorer version 0.3 (specification revision 34)
	Noise Explorer can either generate models or render results, and the parameters
	for either must be invoked exclusively.
	
	Model generation:
	--generate=(proverif|json): Specify output format.
	--pattern=[file]: Specify input pattern file (required).
	--attacker=(active|passive): Specify attacker type (default: active).
	
	Results rendering:
	--render=(handshake|message): Render results from ProVerif output files into HTML.
	--pattern=[file]: Specify input pattern file (required).
	--activeModel=[file]: Specify ProVerif active attacker model (required for --render=message).
	--activeResults=[file]: Specify active results file for --render (required).
	--passiveResults=[file]: Specify passive results file for --render (required).

	Help:
	--help: View this help text.
```

### Requirements
1. [Node](https://nodejs.org).
2. [ProVerif](http://prosecco.gforge.inria.fr/personal/bblanche/proverif/).

### Preparation
1. Install `proverif` in your `$PATH`.
1. `cd src`
2. `make dependencies`
3. `make parser`

### Usage
`node noiseExplorer --help`

### Model Generation
To quickly translate all Noise handshake patterns in the `patterns` directory to ProVerif models, simply run `make models` after completing the steps outlined in the Preparation section of this document. The models will be available in the `models` directory.

### Author and License
Authored by Nadim Kobeissi and released under the GNU General Public License, version 3.
