const exec = require('child_process').exec;
const conventionalCommitsParser = require('conventional-commits-parser');
const fs = require('fs');

const patch = ['fix', 'refactor', 'opt', 'dep'];
const minor = ['feat', 'perf'];
const major = ['rewrite', 'breaking change', 'breaking changes', 'breaking'];
const scopes = ['parsing','codegen','testgen','web','pv','go','rust','wasm'];
const norelease = ['docs', 'style', 'test'];

let changeType = {
    "parsing": {
        name: "parsing",
        major: false,
        minor: false,
        patch: false
    },
    "codegen": {
        name: "codegen",
        major: false,
        minor: false,
        patch: false
    },
    "testgen": {
        name: "testgen",
        major: false,
        minor: false,
        patch: false
    },
    "web": {
        name: "web",
        major: false,
        minor: false,
        patch: false
    },
    "pv": {
        name: "pv",
        major: false,
        minor: false,
        patch: false
    },
    "go": {
        name: "go",
        major: false,
        minor: false,
        patch: false
    },
    "rust": {
        name: "rust",
        major: false,
        minor: false,
        patch: false
    },
    "wasm": {
        name: "wasm",
        major: false,
        minor: false,
        patch: false
    }
};

let isMajor = false;
let isMinor = false;
let isPatch = false;
let change = false;

let changelog = {
    codegen: ['- Code Generation:\n'],
    go: ['- Go:\n'],
    misc: ['- Miscelaneous:\n'],
    parsing: ['- Parsing:\n'],
    pv: ['- ProVerif:\n'],
    rust: ['- Rust:\n'],
    testgen: ['- Test Generation:\n'],
    wasm: ['- WebAssembly:\n'],
    web: ['- Webpage:\n'],
};

exec('git cherry -v master', function(error, stdout, stderr) {
    if (error) {
        console.log(error.code);
    }
    let ver = require('../versions.json');
    
    let tmp = [];
    let parsedCommits = [];
    
    stdout.split('\n').forEach((commit) => {
        tmp.push(commit.split(' '));
    });
    tmp.pop();
    tmp.forEach((arr) => {
        arr.shift();
        arr.shift();
        parsedCommits.push(conventionalCommitsParser.sync(arr.join(' ')));
        
    });
    parsedCommits.forEach((commit)=> {
        if ((commit.scope != null) && scopes.includes(commit.scope.toLowerCase())) {
            if (patch.includes(commit.type.toLowerCase())) {
                changeType[`${commit.scope}`].patch = true;
                isPatch = true;
                changelog[commit.scope].push(`\t- _${commit.header}_.\n`);
            }
            else if (minor.includes(commit.type.toLowerCase())) {
                changeType[`${commit.scope}`].minor = true;
                isMinor = true;
                changelog[commit.scope].push(`\t- ${commit.header}.\n`);
            }
            else if (major.includes(commit.type.toLowerCase())||(commit.footer != null && commit.footer.toLowerCase().includes('breaking change')||commit.footer.toLowerCase().includes('rewrite')||commit.footer.toLowerCase().includes('breaking'))) {
                changeType[`${commit.scope}`].major = true;
                isMajor = true;
                changelog[commit.scope].push(`\t- **${commit.header}.**\n`);
            }
            change = true;
        }
        else if (commit.header != null) {
            changelog['misc'].push(`\t- _${commit.header}._\n`);
            change = true;
        }
    });
    if (change) {
        if (isMajor||isMinor||isPatch) {
            if (isMajor) {
                ver[`major_engine`]++;
            }
            else if (isMinor) {
                ver[`minor_engine`]++;
            }
            if (isPatch) {
                ver[`patch_engine`]++;
            }
            Object.values(changeType).forEach((scope) => {
                if (scope.major) {
                    ver[`major_${scope.name}`]++;
                }
                else if (scope.minor) {
                    ver[`minor_${scope.name}`]++;
                }
                else if (scope.patch) {
                    ver[`patch_${scope.name}`]++;
                }
            });
            fs.writeFileSync('../versions.json', JSON.stringify(ver), 'utf8');
        }
        let changelogString = "";
        Object.values(changelog).forEach((scope) => {
            if (scope.length > 1) {
                changelogString += (`${scope.join('')}\n`);
            }
        });
        let oldChangelog = fs.readFileSync('../../CHANGELOG.md').toString();
        fs.writeFileSync('../../CHANGELOG.md', `## Noise Explorer v${ver['major_engine']}.${ver['minor_engine']}.${ver['patch_engine']}\n${changelogString}\n${oldChangelog}`);
    
        let readme = fs.readFileSync('../../README.md').toString().split('\n');
        readme[1] = `## Version ${ver['major_engine']}.${ver['minor_engine']}.${ver['patch_engine']}, based on Noise Protocol Revision 34.`;
        fs.writeFileSync('../../README.md', readme.join('\n'));
        
        let crateCargo = fs.readFileSync('../../implementations/rs/Cargo.toml').toString().replace(/version = "(.*?)"/g, `version = "${ver['major_rust']}.${ver['minor_rust']}.${ver['patch_rust']}"`);
        fs.writeFileSync('../../implementations/rs/Cargo.toml', crateCargo);
        
        let package = fs.readFileSync('../package.json').toString().split('\n');
        package[2] = `  "version": "${ver['major_engine']}.${ver['minor_engine']}.${ver['patch_engine']}",`;
        fs.writeFileSync('../package.json', package.join('\n'));
    }
});