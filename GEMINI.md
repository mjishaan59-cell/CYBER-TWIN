# Repository Workflow Rules

## Always Commit and Push Verified Changes to GitHub

- After completing any code, configuration, or documentation task in this repository:
  1. **Verify first**: Run the relevant test suite (e.g., `python manage.py test`) and checks after final edits and confirm they pass before committing.
  2. **Inspect & protect secrets**: Check `git status` and stage only task-relevant files (`git add <paths>`). Never stage or commit secrets, `.env` files, API tokens, or key files (`*.pem`, `*.key`), and never bypass `.gitignore`.
  3. **Commit & push automatically**: Create a clear, descriptive commit and push immediately to the tracked remote branch (`git push origin main`, or the active branch) without waiting for a separate prompt.
  4. **Report status**: Include the pushed commit hash and branch in the final response.
- **Exceptions**: Skip pushing and notify the user immediately if tests fail, required checks are blocked, or uncommitted changes include sensitive data or merge conflicts.
