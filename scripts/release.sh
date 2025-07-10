#!/bin/bash

# scripts/release.sh
# Manual release script for Frank Go SDK

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to get current version
get_current_version() {
    local version=$(grep "const Version" types.go | sed 's/.*Version = "\(.*\)".*/\1/')
    echo "$version"
}

# Function to get latest git tag
get_latest_tag() {
    local tag=$(git describe --tags --abbrev=0 2>/dev/null || echo "v0.0.0")
    echo "$tag"
}

# Function to increment version
increment_version() {
    local version=$1
    local type=$2

    IFS='.' read -ra VERSION_PARTS <<< "$version"
    local major=${VERSION_PARTS[0]}
    local minor=${VERSION_PARTS[1]}
    local patch=${VERSION_PARTS[2]}

    case $type in
        major)
            major=$((major + 1))
            minor=0
            patch=0
            ;;
        minor)
            minor=$((minor + 1))
            patch=0
            ;;
        patch)
            patch=$((patch + 1))
            ;;
        *)
            print_error "Invalid version type: $type"
            exit 1
            ;;
    esac

    echo "$major.$minor.$patch"
}

# Function to generate changelog
generate_changelog() {
    local from_tag=$1
    local to_tag=$2

    print_status "Generating changelog from $from_tag to $to_tag"

    echo "## What's Changed"
    echo ""

    # Get commits between tags
    local commits
    if [ "$from_tag" = "v0.0.0" ]; then
        commits=$(git log --oneline --pretty=format:"- %s" HEAD)
    else
        commits=$(git log --oneline --pretty=format:"- %s" ${from_tag}..HEAD)
    fi

    # Categorize commits
    echo "### Features"
    echo "$commits" | grep -E "^- feat" | head -20 || echo "- No new features"
    echo ""

    echo "### Bug Fixes"
    echo "$commits" | grep -E "^- fix" | head -20 || echo "- No bug fixes"
    echo ""

    echo "### Other Changes"
    echo "$commits" | grep -vE "^- (feat|fix)" | head -10 || echo "- No other changes"
    echo ""
}

# Function to update version in files
update_version_in_files() {
    local version=$1

    print_status "Updating version to $version in source files"

    # Update types.go
    sed -i.bak "s/const Version = \".*\"/const Version = \"$version\"/" types.go
    rm types.go.bak

    # Update go.mod if it has version info
    if grep -q "// v" go.mod; then
        sed -i.bak "s|// v.*|// v$version|" go.mod
        rm go.mod.bak
    fi

    print_success "Version updated in source files"
}

# Function to run tests
run_tests() {
    print_status "Running tests"

    if ! go test ./...; then
        print_error "Tests failed"
        exit 1
    fi

    print_success "All tests passed"
}

# Function to build binaries
build_binaries() {
    local version=$1

    print_status "Building binaries for version $version"

    mkdir -p dist

    # Build for different platforms
    GOOS=linux GOARCH=amd64 go build -ldflags="-X main.version=$version" -o dist/frank-go-sdk-linux-amd64
    GOOS=darwin GOARCH=amd64 go build -ldflags="-X main.version=$version" -o dist/frank-go-sdk-darwin-amd64
    GOOS=darwin GOARCH=arm64 go build -ldflags="-X main.version=$version" -o dist/frank-go-sdk-darwin-arm64
    GOOS=windows GOARCH=amd64 go build -ldflags="-X main.version=$version" -o dist/frank-go-sdk-windows-amd64.exe

    print_success "Binaries built successfully"
}

# Function to create git tag
create_git_tag() {
    local version=$1
    local changelog=$2

    print_status "Creating git tag v$version"

    # Create annotated tag with changelog
    git tag -a "v$version" -m "Release v$version

$changelog"

    print_success "Git tag v$version created"
}

# Function to push changes
push_changes() {
    local version=$1

    print_status "Pushing changes and tags to remote"

    git push origin main
    git push origin "v$version"

    print_success "Changes pushed to remote"
}

# Function to create GitHub release
create_github_release() {
    local version=$1
    local changelog=$2

    print_status "Creating GitHub release for v$version"

    # Create release notes file
    echo "# Release v$version" > release_notes.md
    echo "" >> release_notes.md
    echo "$changelog" >> release_notes.md

    # Create GitHub release
    if command_exists gh; then
        gh release create "v$version" \
            --title "Release v$version" \
            --notes-file release_notes.md \
            --latest \
            dist/*

        # Clean up
        rm -f release_notes.md

        print_success "GitHub release created successfully"
    else
        print_warning "GitHub CLI not found. Please create the release manually."
        print_status "Release notes saved to release_notes.md"
    fi
}

# Function to show help
show_help() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -t, --type TYPE     Release type (patch, minor, major). Default: patch"
    echo "  -v, --version VER   Specific version to release (overrides --type)"
    echo "  -d, --dry-run       Show what would be done without making changes"
    echo "  -h, --help          Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                  # Create a patch release"
    echo "  $0 --type minor     # Create a minor release"
    echo "  $0 --type major     # Create a major release"
    echo "  $0 --version 2.1.0  # Create a specific version"
    echo "  $0 --dry-run        # Show what would be done"
    echo ""
}

# Main function
main() {
    local release_type="patch"
    local specific_version=""
    local dry_run=false

    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -t|--type)
                release_type="$2"
                shift 2
                ;;
            -v|--version)
                specific_version="$2"
                shift 2
                ;;
            -d|--dry-run)
                dry_run=true
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done

    # Validate release type
    if [ -z "$specific_version" ] && [[ ! "$release_type" =~ ^(patch|minor|major)$ ]]; then
        print_error "Invalid release type: $release_type"
        show_help
        exit 1
    fi

    # Check if we're in a git repository
    if ! git rev-parse --git-dir > /dev/null 2>&1; then
        print_error "Not in a git repository"
        exit 1
    fi

    # Check if we're on main branch
    local current_branch=$(git branch --show-current)
    if [ "$current_branch" != "main" ]; then
        print_error "Not on main branch (currently on: $current_branch)"
        exit 1
    fi

    # Check if working directory is clean
    if [ -n "$(git status --porcelain)" ]; then
        print_error "Working directory is not clean"
        exit 1
    fi

    # Get current version and latest tag
    local current_version=$(get_current_version)
    local latest_tag=$(get_latest_tag)

    print_status "Current version: $current_version"
    print_status "Latest tag: $latest_tag"

    # Determine new version
    local new_version
    if [ -n "$specific_version" ]; then
        new_version="$specific_version"
    else
        new_version=$(increment_version "$current_version" "$release_type")
    fi

    print_status "New version: $new_version"

    # Check if there are changes since last release
    local latest_tag_clean=${latest_tag#v}
    if [ "$latest_tag_clean" != "0.0.0" ]; then
        local commits_since_release=$(git rev-list --count ${latest_tag}..HEAD)
        if [ "$commits_since_release" -eq 0 ]; then
            print_warning "No commits since last release ($latest_tag)"
            read -p "Continue anyway? (y/N): " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                exit 1
            fi
        fi
    fi

    # Generate changelog
    local changelog=$(generate_changelog "$latest_tag" "HEAD")

    if [ "$dry_run" = true ]; then
        print_status "DRY RUN - The following actions would be performed:"
        echo ""
        echo "1. Update version in files to: $new_version"
        echo "2. Run tests"
        echo "3. Build binaries"
        echo "4. Commit changes"
        echo "5. Create git tag: v$new_version"
        echo "6. Push changes and tags"
        echo "7. Create GitHub release"
        echo ""
        echo "Changelog:"
        echo "$changelog"
        exit 0
    fi

    # Confirm with user
    echo ""
    print_status "Release Summary:"
    echo "  Current version: $current_version"
    echo "  New version: $new_version"
    echo "  Release type: $release_type"
    echo ""
    echo "Changelog:"
    echo "$changelog"
    echo ""

    read -p "Proceed with release? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_status "Release cancelled"
        exit 0
    fi

    # Perform release steps
    print_status "Starting release process for v$new_version"

    # Update version in files
    update_version_in_files "$new_version"

    # Run tests
    run_tests

    # Build binaries
    build_binaries "$new_version"

    # Commit changes
    git add .
    git commit -m "chore: prepare release v$new_version"

    # Create git tag
    create_git_tag "$new_version" "$changelog"

    # Push changes
    push_changes "$new_version"

    # Create GitHub release
    create_github_release "$new_version" "$changelog"

    print_success "Release v$new_version completed successfully!"
    print_status "Release URL: https://github.com/$(git remote get-url origin | sed 's/.*github.com[:/]\(.*\)\.git/\1/')/releases/tag/v$new_version"
}

# Check dependencies
check_dependencies() {
    local missing_deps=()

    if ! command_exists git; then
        missing_deps+=("git")
    fi

    if ! command_exists go; then
        missing_deps+=("go")
    fi

    if [ ${#missing_deps[@]} -ne 0 ]; then
        print_error "Missing dependencies: ${missing_deps[*]}"
        exit 1
    fi

    if ! command_exists gh; then
        print_warning "GitHub CLI not found. GitHub releases will need to be created manually."
    fi
}

# Run dependency check and main function
check_dependencies
main "$@"