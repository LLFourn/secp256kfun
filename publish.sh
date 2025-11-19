#!/bin/bash
set -e

# Publish crates in dependency order
# Each publish waits for the previous to be indexed on crates.io

# Format: "directory:crate_name"
CRATES=(
    "arithmetic_macros:secp256kfun_arithmetic_macros"
    "secp256kfun:secp256kfun"
    "sigma_fun:sigma_fun"
    "vrf_fun:vrf_fun"
    "ecdsa_fun:ecdsa_fun"
    "schnorr_fun:schnorr_fun"
)

# Time to wait between publishes (in seconds)
WAIT_TIME=30

# Check if a version exists on crates.io
check_version_exists() {
    local crate_name=$1
    local version=$2

    echo "🔍 Checking if $crate_name $version exists on crates.io..."
    if cargo search "$crate_name" --limit 1 | grep -q "\"$version\""; then
        return 0  # exists
    else
        return 1  # doesn't exist
    fi
}

# Get version from Cargo.toml
get_version() {
    local dir=$1
    grep '^version = ' "$dir/Cargo.toml" | head -1 | sed 's/version = "\(.*\)"/\1/'
}

echo "Publishing secp256kfun v0.12.0 crates..."
echo ""

for entry in "${CRATES[@]}"; do
    IFS=':' read -r dir crate_name <<< "$entry"
    version=$(get_version "$dir")

    if check_version_exists "$crate_name" "$version"; then
        echo "⏭️  Skipping $crate_name $version (already published)"
        echo ""
        continue
    fi

    echo "📦 Publishing $crate_name $version..."
    cd "$dir"
    cargo publish
    cd ..

    echo "⏳ Waiting ${WAIT_TIME}s for crates.io to index $crate_name..."
    sleep $WAIT_TIME
    echo ""
done

echo ""
echo "✅ All crates published successfully!"
