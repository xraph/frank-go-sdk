#!/bin/bash

# Quick fix for release detection issue
# This script will help diagnose and fix the immediate problem

set -e

echo "🔍 Diagnosing Release Detection Issue"
echo "====================================="

# Check the current commit message
latest_commit=$(git log -1 --pretty=format:"%s")
echo "Latest commit message: '$latest_commit'"

# Check if it's a merge commit
if [[ "$latest_commit" =~ ^Merge\ pull\ request\ #([0-9]+) ]]; then
    pr_number=$(echo "$latest_commit" | sed -n 's/.*#\([0-9]*\).*/\1/p')
    echo "This is a merge commit for PR #$pr_number"

    # Check if it was a release PR
    if command -v gh >/dev/null 2>&1; then
        echo "Checking PR details..."
        pr_info=$(gh pr view $pr_number --json labels,title,headRefName,state 2>/dev/null || echo "")

        if [ -n "$pr_info" ]; then
            pr_title=$(echo "$pr_info" | jq -r '.title // ""')
            pr_labels=$(echo "$pr_info" | jq -r '.labels[]?.name // ""' | tr '\n' ' ')
            pr_branch=$(echo "$pr_info" | jq -r '.headRefName // ""')
            pr_state=$(echo "$pr_info" | jq -r '.state // ""')

            echo "  PR Title: $pr_title"
            echo "  PR Labels: $pr_labels"
            echo "  PR Branch: $pr_branch"
            echo "  PR State: $pr_state"

            # Check if this was a release PR
            if [[ "$pr_title" =~ ^Release\ v[0-9]+\.[0-9]+\.[0-9]+$ ]] || echo "$pr_labels" | grep -q "release"; then
                version=$(echo "$pr_title" | sed -n 's/^Release v\([0-9]*\.[0-9]*\.[0-9]*\)$/\1/p')
                echo "✅ This WAS a release PR for version: $version"

                # Check if the release was actually created
                if git tag -l "v$version" | grep -q "v$version"; then
                    echo "✅ Git tag v$version exists"
                else
                    echo "❌ Git tag v$version is missing"

                    # Offer to create the tag
                    echo "Would you like to create the missing tag? (y/n)"
                    read -r create_tag
                    if [[ $create_tag == "y" || $create_tag == "Y" ]]; then
                        git tag -a "v$version" -m "Release v$version"
                        git push origin "v$version"
                        echo "✅ Created and pushed tag v$version"
                    fi
                fi

                # Check if GitHub release exists
                if gh release view "v$version" >/dev/null 2>&1; then
                    echo "✅ GitHub release v$version exists"
                else
                    echo "❌ GitHub release v$version is missing"

                    # Offer to create the release
                    echo "Would you like to create the missing GitHub release? (y/n)"
                    read -r create_release
                    if [[ $create_release == "y" || $create_release == "Y" ]]; then
                        gh release create "v$version" \
                            --title "Release v$version" \
                            --notes "Automated release v$version" \
                            --latest
                        echo "✅ Created GitHub release v$version"
                    fi
                fi
            else
                echo "❌ This was NOT a release PR"
            fi
        else
            echo "❌ Could not fetch PR information"
        fi
    else
        echo "❌ GitHub CLI (gh) not available"
    fi
else
    echo "This is not a merge commit"

    # Check if it's a direct release commit
    if [[ "$latest_commit" =~ ^chore:\ prepare\ release\ v[0-9]+\.[0-9]+\.[0-9]+ ]]; then
        version=$(echo "$latest_commit" | sed 's/chore: prepare release v\([0-9]*\.[0-9]*\.[0-9]*\).*/\1/')
        echo "✅ This IS a direct release commit for version: $version"
    else
        echo "❌ This is not a release commit"
    fi
fi

echo ""
echo "🔧 RECOMMENDATIONS:"
echo "==================="

echo "1. Update your .github/workflows/release.yml with the enhanced detection logic"
echo "2. The new logic will handle:"
echo "   - Direct release commits"
echo "   - Merge commits from release branches"
echo "   - Merge commits from release PRs"
echo "   - Recent commits containing release preparation"
echo ""
echo "3. Test the fix by triggering a manual release:"
echo "   gh workflow run release.yml -f release_type=patch"
echo ""
echo "4. Monitor the workflow logs to ensure the detection works correctly"

# Check for stuck workflows
echo ""
echo "📊 Checking for stuck workflows..."
if command -v gh >/dev/null 2>&1; then
    running_workflows=$(gh run list --workflow=release.yml --status=in_progress --limit 5 --json databaseId,conclusion,status,createdAt)

    if [ "$running_workflows" != "[]" ]; then
        echo "Found running workflows:"
        echo "$running_workflows" | jq -r '.[] | "ID: \(.databaseId), Status: \(.status), Created: \(.createdAt)"'

        echo ""
        echo "Would you like to cancel these workflows? (y/n)"
        read -r cancel_workflows
        if [[ $cancel_workflows == "y" || $cancel_workflows == "Y" ]]; then
            echo "$running_workflows" | jq -r '.[].databaseId' | while read -r run_id; do
                gh run cancel "$run_id"
                echo "Cancelled workflow run: $run_id"
            done
        fi
    else
        echo "No stuck workflows found"
    fi
fi

echo ""
echo "🎉 Diagnosis complete!"
echo "Update your workflow file with the enhanced logic to fix the issue."