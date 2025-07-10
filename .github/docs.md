# Automated Release System

This repository uses an automated release system that manages version bumping, changelog generation, and GitHub releases. The system is designed to prevent duplicate release PRs and ensure consistent releases.

## How It Works

### 1. Automated Release Detection

The system automatically detects when a release should be created based on:
- New commits with conventional commit messages (`feat:`, `fix:`, etc.)
- Manually triggered workflow runs
- Daily schedule checks for unreleased changes

### 2. Release PR Management

When a release is needed:
- **First time**: Creates a new release PR with version bump and changelog
- **Subsequent runs**: Updates the existing release PR instead of creating a new one
- **Never duplicates**: Prevents multiple release PRs from being open simultaneously

### 3. Release Process

1. **Preparation**: Version is bumped in source files, changelog is generated
2. **Validation**: Comprehensive checks ensure release quality
3. **Approval**: Automated approval for bot-created PRs (optional manual approval)
4. **Release**: Upon merge, creates git tag and GitHub release with artifacts

## Triggering Releases

### Automatic Triggers

- **Push to main**: Checks for unreleased changes and creates release PR if needed
- **Daily schedule**: Runs at 9 AM UTC to check for pending releases
- **Commit messages**: Follows conventional commits for version detection

### Manual Triggers

#### GitHub Actions Workflow Dispatch
```bash
# Trigger via GitHub UI or CLI
gh workflow run release.yml -f release_type=minor
```

#### Manual Release Script
```bash
# Make the script executable
chmod +x scripts/release.sh

# Create a patch release
./scripts/release.sh

# Create a minor release
./scripts/release.sh --type minor

# Create a major release
./scripts/release.sh --type major

# Create a specific version
./scripts/release.sh --version 2.1.0

# Dry run to see what would happen
./scripts/release.sh --dry-run
```

## Release Types

### Version Bumping Rules

The system automatically determines the appropriate version bump based on commit messages:

- **Major** (`x.0.0`): Breaking changes, commits with `BREAKING CHANGE:` or `feat!:`
- **Minor** (`x.y.0`): New features, commits with `feat:`
- **Patch** (`x.y.z`): Bug fixes, commits with `fix:`, `perf:`, `refactor:`

### Commit Message Examples

```bash
# Will trigger a minor release
git commit -m "feat: add new authentication method"

# Will trigger a patch release
git commit -m "fix: resolve session timeout issue"

# Will trigger a major release
git commit -m "feat!: change API authentication format

BREAKING CHANGE: API now requires OAuth2 instead of API keys"

# Will not trigger a release
git commit -m "docs: update README"
git commit -m "ci: update GitHub Actions"
```

## Configuration

### Environment Variables

Set these in your repository secrets or environment:

```bash
# Required
GITHUB_TOKEN=ghp_xxxxxxxxxxxx  # GitHub token with repo access

# Optional
RELEASE_BRANCH_PREFIX=release/  # Default: "release/"
CHANGELOG_FILE=CHANGELOG.md     # Default: "CHANGELOG.md"
```

### Release Configuration

Edit `.github/release.yml` to customize:

```yaml
# Version bump rules
release_rules:
  - type: feat
    release: minor
  - type: fix
    release: patch
  - breaking: true
    release: major

# Files to update during release
files_to_update:
  - file: "types.go"
    pattern: 'const Version = ".*"'
    replacement: 'const Version = "${version}"'
```

## Workflows

### 1. Main Release Workflow (`.github/workflows/release.yml`)

**Triggers:**
- Push to main branch
- Daily schedule (9 AM UTC)
- Manual workflow dispatch

**Jobs:**
- `prepare-release`: Detects if release is needed, finds existing PRs
- `create-or-update-release-pr`: Creates new or updates existing release PR
- `create-release`: Creates GitHub release when release commit is merged

### 2. Release PR Workflow (`.github/workflows/release-pr.yml`)

**Triggers:**
- Pull request with `release` label

**Jobs:**
- `validate-release`: Comprehensive validation of release PR
- `security-scan`: Security scanning with gosec
- `auto-approve`: Auto-approval for bot-created PRs
- `ready-to-merge`: Adds ready-to-merge label when all checks pass

## Validation Checks

Release PRs undergo thorough validation:

### Code Quality
- ✅ All tests pass
- ✅ Code builds successfully
- ✅ Multi-platform build testing
- ✅ Linting checks (if configured)

### Release Integrity
- ✅ Version consistency across files
- ✅ Changelog validation
- ✅ Go module validation
- ✅ Breaking change detection

### Security
- ✅ Security scanning with gosec
- ✅ Vulnerability checks
- ✅ Dependency validation

## Customization

### Adding Custom Validation

Edit `.github/workflows/release-pr.yml` to add custom checks:

```yaml
- name: Custom validation
  run: |
    # Your custom validation logic
    echo "Running custom validation..."
    # Exit with non-zero code to fail the check
```

### Modifying Version Files

Edit the `files_to_update` section in `.github/release.yml`:

```yaml
files_to_update:
  - file: "your-file.go"
    pattern: 'const MyVersion = ".*"'
    replacement: 'const MyVersion = "${version}"'
```

### Custom Changelog Format

Edit the changelog generation in `scripts/release.sh`:

```bash
generate_changelog() {
    # Your custom changelog logic
    echo "## Custom Changelog Format"
    # ...
}
```

## Troubleshooting

### Common Issues

#### "No release PR found but one expected"
- Check if the PR has the `release` label
- Ensure the PR title matches the pattern `Release v{version}`

#### "Version mismatch between files"
- Make sure all version references are updated consistently
- Check the `files_to_update` configuration

#### "Release workflow not triggering"
- Verify the workflow file syntax
- Check if the repository has the required permissions
- Ensure the GitHub token has sufficient permissions

### Debug Mode

Enable debug logging in workflows:

```yaml
env:
  ACTIONS_STEP_DEBUG: true
  ACTIONS_RUNNER_DEBUG: true
```

### Manual Intervention

If the automated system encounters issues:

1. **Check existing PRs**: `gh pr list --label release`
2. **Close problematic PR**: `gh pr close <number>`
3. **Trigger manual release**: `gh workflow run release.yml`
4. **Use manual script**: `./scripts/release.sh`

## Best Practices

### Commit Messages
- Use conventional commit format
- Be descriptive about changes
- Include breaking change notes when applicable

### Release Timing
- Batch related changes together
- Avoid releasing during high-traffic periods
- Test releases in development environments first

### Version Strategy
- Follow semantic versioning strictly
- Document breaking changes thoroughly
- Consider deprecation periods for major changes

## Monitoring

### GitHub Actions
- Monitor workflow runs in the "Actions" tab
- Check for failed releases and address issues promptly
- Review release PR comments for validation results

### Release Health
- Monitor download statistics
- Track issue reports after releases
- Maintain backward compatibility when possible

## Security Considerations

### Token Permissions
- Use minimal required permissions for GitHub tokens
- Regularly rotate tokens
- Monitor token usage

### Release Artifacts
- Verify checksums of release artifacts
- Sign releases for critical software
- Scan for vulnerabilities before release

## Support

For issues with the release system:

1. Check the workflow logs in GitHub Actions
2. Review this documentation
3. Check for known issues in the repository
4. Open an issue with detailed logs and context

## Examples

### Typical Release Flow

1. **Development**: Make changes with conventional commits
2. **Automatic**: System detects changes and creates release PR
3. **Review**: Automated validation runs and reports results
4. **Merge**: PR is merged after validation passes
5. **Release**: GitHub release is created automatically

### Manual Release Example

```bash
# Check what would be released
./scripts/release.sh --dry-run

# Create a minor release
./scripts/release.sh --type minor

# Release completes automatically
```

This system ensures consistent, reliable releases while minimizing manual intervention and preventing duplicate release PRs.