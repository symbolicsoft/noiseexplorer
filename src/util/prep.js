const exec = require('child_process').exec;
const conventionalCommitsParser = require('conventional-commits-parser');
const fs = require('fs');

const patch = ['fix', 'refactor', 'opt', 'dep'];
const minor = ['feat', 'perf'];
const major = ['rewrite', 'breaking change', 'breaking changes', 'breaking'];
const norelease = ['docs', 'style', 'test'];
const scopes = ['parsing','codegen','testgen','web','pv','go','rust','wasm'];

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
                ver[`patch_${commit.scope}`]++;
                isPatch = true;
                changelog[commit.scope].push(`\t- _${commit.header}_.\n`);
            }
            else if (minor.includes(commit.type.toLowerCase())) {
                ver[`minor_${commit.scope}`]++;
                isMinor = true;
                changelog[commit.scope].push(`\t- ${commit.header}.\n`);
            }
            else if (major.includes(commit.type.toLowerCase())||(commit.footer != null && commit.footer.toLowerCase().includes('breaking change')||commit.footer.toLowerCase().includes('rewrite')||commit.footer.toLowerCase().includes('breaking'))) {
                ver[`major_${commit.scope}`]++;
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
            fs.writeFileSync('../versions.json', JSON.stringify(ver), 'utf8');
        }
        let changelogString = "";
        Object.values(changelog).forEach((scope) => {
            if (scope.length > 1) {
                changelogString += (`${scope.join('')}\n`);
            }
        });
        const oldChangelog = fs.readFileSync('../../CHANGELOG.md').toString();
        fs.writeFileSync('../../CHANGELOG.md', `## Noise Explorer v${ver['major_engine']}.${ver['minor_engine']}.${ver['patch_engine']}\n${changelogString}\n${oldChangelog}`);
    }
});
