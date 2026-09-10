## What and why

<!-- What problem does this solve, and why this approach? -->

## Related issue

<!-- Closes #… -->

## What I tested

<!-- Which platform, which servers, which cases. -->

## What I did not do

<!-- Missing tests, untested platforms, known limitations. Say it here rather
     than letting it be found in review. -->

## Checklist

- [ ] `cargo fmt --all --check`
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] `cargo test --workspace`
- [ ] `cargo deny check`
- [ ] Frontend `typecheck`, `lint` and `test` pass
- [ ] Documentation updated in the same commit as the behaviour change
- [ ] New user-visible strings added to `locales/en/` and wrapped in `t()`
- [ ] No secret can reach a log, an error message or a panic payload
- [ ] Commits follow Conventional Commits
