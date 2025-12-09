module.exports = {
    "branches": [
        "release",
        {
            "name": "main",
            "prerelease": "rc"
        }
    ],
    "plugins": [
        ["@semantic-release/commit-analyzer", {
            "preset": "conventionalcommits",
            "releaseRules": [
                { "type": "feat", "release": "minor" },
                { "type": "fix", "release": "patch" },
                { "type": "perf", "release": "patch" },
                { "type": "revert", "release": "patch" },
                { "type": "refactor", "release": "patch" },
                { "type": "docs", "release": false },
                { "type": "style", "release": false },
                { "type": "test", "release": false },
                { "type": "build", "release": false },
                { "type": "ci", "release": false },
                { "type": "chore", "release": false }
            ]
        }],
        ["@semantic-release/release-notes-generator", { "preset": "conventionalcommits" }],
        ["@semantic-release/exec", {
            "prepareCmd": "node -e \"const fs=require('fs'),toml=require('@iarna/toml');let version='${nextRelease.version}';version=version.replace(/-rc\\\\./g,'rc');const pyprojectFile='pyproject.toml';const pyprojectData=toml.parse(fs.readFileSync(pyprojectFile,'utf8'));const packageName=pyprojectData.project.name;pyprojectData.project.version=version;fs.writeFileSync(pyprojectFile,toml.stringify(pyprojectData));const uvLockFile='uv.lock';const uvLockData=toml.parse(fs.readFileSync(uvLockFile,'utf8'));const packageIndex=uvLockData.package.findIndex(p=>p.name===packageName);if(packageIndex!==-1){uvLockData.package[packageIndex].version=version;fs.writeFileSync(uvLockFile,toml.stringify(uvLockData));}\""
        }],
        ["@semantic-release/changelog", {}],
        ["@semantic-release/git", {
            "assets": ["CHANGELOG.md", "pyproject.toml", "uv.lock"],
            "message": "chore(release): ${nextRelease.version}\n\n${nextRelease.notes}\n\nSigned-off-by: semantic-release-bot <semantic-release-bot@martynus.net>"
        }],
        ["@semantic-release/github", {}]
    ]
}
