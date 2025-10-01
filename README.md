# GitHub action `negrutiu/nsis-install-plugin`

[![Static Badge](https://img.shields.io/badge/GitHub%20Marketplace-negrutiu%2Fnsis--install--plugin-blue?style=flat-square&logo=github)
](https://github.com/marketplace/actions/install-nsis-plugin)

This GitHub action downloads and installs [NSIS](https://nsis.sourceforge.io/Main_Page) plugins onto an existing NSIS installation.  
It runs on all GitHub-hosted runners (Windows, Linux, macOS).  
It can download plugins from GitHub releases, or from a custom URL.  
Already installed plugins are overwritten if a newer version is found.

# Action Inputs

### `github-owner`
### `github-repo`
### `github-tag`

GitHub **owner**, **repository**, and **tag** are used to construct the URL to download the plugin from. `github-owner` and `github-repo` are required, while `github-tag` defaults to `latest`.

### `github-asset-regex`

Regular expression to match the asset name in the GitHub release. The first matching asset will be downloaded.

### `github-token`

Custom GitHub token used for authentication when accessing the GitHub API. This is used to avoid running into GitHub rate limits when downloading release assets. Defaults to `${{github.token}}`, which is automatically provided by GitHub Actions.

### `url`

Custom URL to download the plugin from. URL downloads and GitHub downloads are mutually exclusive, either `url` or `github-*` must be specified.

### `plugin-name`

Optional plugin name used as destination directory name. If not specified, the plugin name is inferred from the file names.

### `plugin-x86-ansi-regex`
### `plugin-x86-unicode-regex`
### `plugin-amd64-unicode-regex`

Optional regular expressions to identify the plugin DLL files for each architecture and character set. All regexes are case-insensitive and matched against the relative path in the plugin archive (e.g. "Plugins/x86-unicode/plugin.dll").

If not specified, the plugin architecture and character set are heuristically determined by analyzing the PE file headers. The heuristics may fail for some plugins, in which case you can use these inputs to explicitly specify the regex patterns.

### `plugin-ignore-regex`

Optional regular expression to ignore certain files or directories in the plugin archive (e.g. `.*Debug.*`).
Useful when the plugin archive contains development files that you don't want to install.

### `nsis-directory`

Optional NSIS installation directory to install the plugin to. By default, the action will try to find all NSIS installations on the system and install the plugin to all of them.

### `nsis-overwrite-newer`

Overwrite existing plugin files only if the downloaded file is newer. To check if the downloaded file is newer, the action compares the `TimeDateStamp` value in the PE headers of the two files.

Defaults to `true`.

# Action Outputs

No outputs.

# Usage

```yaml
name: Install NSIS plugin
jobs:
  build-project:
    steps:
    - name: Install `NScurl` from GitHub
      uses: negrutiu/nsis-install-plugin@v1
      with:
        github-owner: negrutiu
        github-repo: nsis-nscurl
        github-asset-regex: NScurl\.zip

    - name: Install `NsArray` from web
      uses: negrutiu/nsis-install-plugin@v1
      with:
        url: https://nsis.sourceforge.io/mediawiki/images/9/97/NsArray.zip
```

# Related topics

- At the time of writing, the `windows-2025` runner image comes with no NSIS installation.
You can use the [negrutiu/nsis-install](https://github.com/marketplace/actions/install-nsis-compiler) action to install NSIS on the runner.