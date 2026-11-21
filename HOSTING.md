# Repository hosting

Development happens on GitHub at [github.com/openape-ai/escapes](https://github.com/openape-ai/escapes). Clone, branch, push and open pull requests there:

```sh
git clone git@github.com:openape-ai/escapes.git
```

The former hosts repos.openape.ai (ape-git) and git.openape.ai (Forgejo) were retired in November 2026. Their repository URLs redirect to GitHub and refuse pushes; existing clones should set `origin` to the GitHub URL above.

## Releases

There is no CI. Bump `version` in `Cargo.toml`, merge, tag `v<version>` on `main` and push the tag, then run `scripts/release.sh --dry-run` and `scripts/release.sh` on a Mac (requirements in the script header). It builds the same assets as earlier releases, which `escapes --update` and `packaging/install.sh` rely on.
