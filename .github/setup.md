# Quick Setup Guide for Automated Releases

## Immediate Fix for Current Issue

The error you encountered is because the `release` label doesn't exist in your repository. Here's how to fix it immediately:

### Option 1: Manual Label Creation (Fastest)

1. Go to your repository on GitHub
2. Click on "Issues" tab
3. Click on "Labels"
4. Click "New label"
5. Create a label with:
    - **Name**: `release`
    - **Description**: `Automated release PR`
    - **Color**: `#0e8a16` (green)

### Option 2: Using GitHub CLI (Recommended)

```bash
# Create the release label
gh label create "release" --description "Automated release PR" --color "0e8a16"

# Verify it was created
gh label list
```

### Option 3: Run the Setup Workflow

1. Go to your repository's "Actions" tab
2. Click on "Repository Setup" workflow
3. Click "Run workflow"
4. This will create all necessary labels and configuration

## Complete Setup Process

### 1. Repository Setup (One-time)

```bash
# Clone your repository
git clone https://github.com/your-org/frank-go-sdk.git
cd frank-go-sdk

# Create the workflow files (copy from the artifacts above)
mkdir -p .github/workflows
mkdir -p scripts

# Copy the workflow files:
# - .github/workflows/release.yml
# - .github/workflows/release-pr.yml
# - .github/workflows/setup.yml
# - scripts/release.sh (make executable)

# Make the script executable
chmod +x scripts/release.sh

# Commit the workflow files
git add .github/workflows/ scripts/
git commit -m "feat: add automated release system"
git push origin main
```

### 2. Run Initial Setup

```bash
# Option A: Via GitHub Actions
# Go to Actions → Repository Setup → Run workflow

# Option B: Via GitHub CLI
gh workflow run setup.yml

# Option C: Manual label creation
gh label create "release" --description "Automated release PR" --color "0e8a16"
gh label create "ready-to-merge" --description "Ready to be merged" --color "0e8a16"
gh label create "automated" --description "Automated by GitHub Actions" --color "0052cc"
```

### 3. Configure Repository Settings

1. **Branch Protection** (Recommended):
    - Go to Settings → Branches
    - Add rule for `main` branch
    - Enable "Require pull request reviews before merging"
    - Enable "Require status checks to pass before merging"

2. **Repository Secrets** (If needed):
    - Go to Settings → Secrets and variables → Actions
    - `GITHUB_TOKEN` is automatically provided
    - Add any additional secrets if required

### 4. Test the System

```bash
# Option A: Make a change with conventional commit
echo "# Test" >> README.md
git add README.md
git commit -m "feat: add test content"
git push origin main

# Option B: Manual trigger
gh workflow run release.yml -f release_type=patch

# Option C: Using the script
./scripts/release.sh --dry-run  # See what would happen
./scripts/release.sh --type patch  # Actually create a release
```

## Troubleshooting

### Common Issues and Solutions

1. **"Label not found" error**:
   ```bash
   # Create missing labels
   gh label create "release" --description "Automated release PR" --color "0e8a16"
   ```

2. **"Permission denied" error**:
    - Check if `GITHUB_TOKEN` has sufficient permissions
    - Ensure repository settings allow Actions to create PRs

3. **"No changes detected" error**:
   ```bash
   # Force a release
   gh workflow run release.yml -f release_type=patch
   ```

4. **"Branch protection" error**:
    - Temporarily disable branch protection
    - Or add the GitHub Actions bot as an admin

### Verification Steps

After setup, verify everything works:

```bash
# 1. Check labels exist
gh label list | grep -E "(release|ready-to-merge|automated)"

# 2. Check workflows are present
ls -la .github/workflows/

# 3. Test the release script
./scripts/release.sh --dry-run

# 4. Check version in types.go
grep "const Version" types.go
```

## Next Steps

1. **Make your first release**:
   ```bash
   # Via script
   ./scripts/release.sh --type patch
   
   # Via GitHub Actions
   gh workflow run release.yml -f release_type=patch
   ```

2. **Configure conventional commits**:
    - Use `feat:` for new features (minor version bump)
    - Use `fix:` for bug fixes (patch version bump)
    - Use `feat!:` or `BREAKING CHANGE:` for major version bump

3. **Customize the system**:
    - Edit `.github/release.yml` for custom rules
    - Modify `scripts/release.sh` for custom behavior
    - Add additional validation steps in workflows

## Example Workflow

```bash
# 1. Make changes with proper commit messages
git add .
git commit -m "feat: add new authentication method"
git push origin main

# 2. System automatically detects the change and creates release PR
# 3. Review the PR (it will have automated validation)
# 4. Merge the PR
# 5. GitHub release is created automatically with built artifacts
```

## Support

If you encounter any issues:

1. Check the GitHub Actions logs
2. Verify all labels exist
3. Ensure the workflows are in the correct location
4. Check repository permissions
5. Review this guide for common solutions

The system is designed to be self-healing - it will create missing labels and handle most edge cases automatically.