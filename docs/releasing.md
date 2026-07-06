# Releasing

`agentic-risk-scan` publishes to PyPI with GitHub Actions and PyPI Trusted
Publishing (OIDC). No API tokens are stored in the repository or in GitHub
secrets. The workflow mints a short-lived token from PyPI at publish time.

## One-Time Setup (maintainer)

Trusted publishing must be registered on PyPI once before the first release.

1. Create the project on PyPI (or use a pending publisher for the first
   release): https://pypi.org/manage/account/publishing/
2. Add a **pending publisher** with these values:
   - PyPI Project Name: `agentic-risk-scan`
   - Owner: `ecoreal`
   - Repository name: `agentic-risk-scan`
   - Workflow name: `publish.yml`
   - Environment name: `pypi`
3. In the GitHub repository, create an environment named `pypi`
   (Settings → Environments). Optionally add required reviewers so a human
   approves each publish.

No PyPI token is ever pasted into GitHub. The `id-token: write` permission on
the `publish` job lets the runner exchange an OIDC token for a scoped upload
token during the run.

## Cutting a Release

1. Update `version` in `pyproject.toml`.
2. Add a matching section to `CHANGELOG.md`.
3. Verify the build locally in a throwaway environment (never install build
   tooling into the project's runtime environment):

   ```bash
   python3 -m venv /tmp/ars-build && /tmp/ars-build/bin/pip install -q build twine
   /tmp/ars-build/bin/python -m build
   /tmp/ars-build/bin/python -m twine check dist/*
   ```

4. Confirm the wheel installs clean and the console script resolves:

   ```bash
   python3 -m venv /tmp/ars-smoke && /tmp/ars-smoke/bin/pip install -q dist/*.whl
   /tmp/ars-smoke/bin/agentic-risk-scan --version
   ```

5. Tag and push the tag, then publish a GitHub Release for that tag.
   Publishing the release triggers `publish.yml`, which builds again on a clean
   runner and uploads to PyPI.

The scanner itself stays dependency-free: `build` and `twine` are release
tooling only and never appear in `pyproject.toml` dependencies.
