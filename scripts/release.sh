#!/bin/bash

# Quick fix for the current release issue
set -e

echo "🔧 Fixing current release state..."

# Check if we have a release commit that needs to be processed
latest_commit=$(git log -1 --pretty=format:"%s")
echo "Latest commit: $latest_commit"

# Check if this is a release commit that didn't get processed
if [[ "$latest_commit" =~ ^chore:\ prepare\ release\ v[0-9]+\.[0-9]+\.[0-9]+ ]]; then
    version=$(echo "$latest_commit" | sed 's/chore: prepare release v\([0-9]*\.[0-9]*\.[0-9]*\).*/\1/')
    echo "Found unprocessed release commit for version: $version"

    # Check if tag already exists
    if git tag -l "v$version" | grep -q "v$version"; then
        echo "✅ Tag v$version already exists"
    else
        echo "❌ Tag v$version is missing - creating it now"

        # Create the tag
        git tag -a "v$version" -m "Release v$version"
        git push origin "v$version"
        echo "✅ Created and pushed tag v$version"

        # Create GitHub release if gh CLI is available
        if command -v gh >/dev/null 2>&1; then
            echo "Creating GitHub release..."

            # Extract release notes if available
            if [ -f CHANGELOG.md ]; then
                # Try to extract release notes for this version
                awk "/^# Changelog for v$version/,/^# Changelog for v[0-9]/ {if (!/^# Changelog for v[0-9]/ || /^# Changelog for v$version/) print}" CHANGELOG.md > release_notes.md
                if [ -s release_notes.md ]; then
                    tail -n +2 release_notes.md > release_notes_clean.md
                    gh release create "v$version" --title "Release v$version" --notes-file release_notes_clean.md
                else
                    gh release create "v$version" --title "Release v$version" --notes "Automated release v$version"
                fi
            else
                gh release create "v$version" --title "Release v$version" --notes "Automated release v$version"
            fi

            echo "✅ GitHub release created for v$version"
        else
            echo "⚠️  GitHub CLI not available - you'll need to create the release manually"
        fi
    fi

    # Clean up the release branch
    branch_name="release/v$version"
    if git ls-remote --heads origin "$branch_name" | grep -q "$branch_name"; then
        git push origin --delete "$branch_name" || echo "Could not delete branch"
        echo "🧹 Cleaned up release branch: $branch_name"
    fi

else
    echo "Current commit is not a release commit"
fi

# Check for any open release PRs that might be stuck
if command -v gh >/dev/null 2>&1; then
    echo ""
    echo "🔍 Checking for stuck release PRs..."

    open_prs=$(gh pr list --state open --label "release" --json number,title,headRefName)
    if [ "$open_prs" != "[]" ]; then
        echo "Found open release PRs:"
        echo "$open_prs" | jq -r '.[] | "PR #\(.number): \(.title) (\(.headRefName))"'

        echo ""
        echo "Options:"
        echo "1. Close stuck PRs: gh pr close <number>"
        echo "2. Delete stuck branches: git push origin --delete <branch_name>"
        echo "3. Or let the fixed workflow handle them"
    else
        echo "✅ No stuck release PRs found"
    fi
fi

echo ""
echo "🎉 Quick fix completed!"
echo ""
echo "Next steps:"
echo "1. Replace your .github/workflows/release.yml with the fixed version"
echo "2. Commit and push the updated workflow"
echo "3. Test with: gh workflow run release.yml -f release_type=patch"