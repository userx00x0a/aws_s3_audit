#!/usr/bin/env bash

# =========================
# Config
# =========================
MAX_PUBLIC_CHECK=10
TMP_FILE=$(mktemp)

# =========================
# Argument parsing
# =========================
if [ -z "$1" ]; then
    echo "Usage: $0 <bucket-name> [profile] [region]"
    exit 1
fi

BUCKET="$1"
PROFILE="$2"
REGION="$3"

AWS_ARGS=()
[ -n "$PROFILE" ] && AWS_ARGS+=(--profile "$PROFILE")
[ -n "$REGION" ] && AWS_ARGS+=(--region "$REGION")

# =========================
# Helpers
# =========================
log() {
    echo -e "$1"
}

section() {
    echo
    echo "==================== $1 ===================="
}

aws_safe() {
    aws "${AWS_ARGS[@]}" "$@" 2>/dev/null
}

# =========================
# Region detection
# =========================
detect_region() {
    if [ -z "$REGION" ]; then
        REGION=$(aws_safe s3api get-bucket-location --bucket "$BUCKET" | jq -r '.LocationConstraint // "us-east-1"')
        AWS_ARGS+=(--region "$REGION")
        log "🌍 Auto-detected region: $REGION"
    fi
}

# =========================
# Permission check
# =========================
check_perm() {
    local name="$1"
    shift
    if aws_safe "$@" >/dev/null; then
        log "  ✅ $name"
        return 0
    else
        log "  ❌ $name"
        return 1
    fi
}

# =========================
# Start
# =========================
log "🔍 Auditing S3 bucket: $BUCKET"
[ -n "$PROFILE" ] && log "👤 Profile: $PROFILE"

detect_region

section "Permission Mapping"
check_perm "List buckets" s3api list-buckets
check_perm "List objects" s3api list-objects-v2 --bucket "$BUCKET"
check_perm "Get bucket ACL" s3api get-bucket-acl --bucket "$BUCKET"
check_perm "Get bucket policy" s3api get-bucket-policy --bucket "$BUCKET"
check_perm "Get public access block" s3api get-public-access-block --bucket "$BUCKET"

# =========================
# Public access
# =========================
section "Public Exposure"

if aws s3api list-objects-v2 --bucket "$BUCKET" --no-sign-request >/dev/null 2>&1; then
    log "🚨 PUBLIC: Bucket is listable without auth"
    PUBLIC=true
else
    log "✅ Not publicly listable"
    PUBLIC=false
fi

# =========================
# Versioning
# =========================
section "Versioning"

versioning=$(aws_safe s3api get-bucket-versioning --bucket "$BUCKET")

if echo "$versioning" | grep -q '"Status": "Enabled"'; then
    log "✅ Versioning enabled"
else
    log "❌ Versioning disabled"
fi

# =========================
# ACL Analysis
# =========================
section "ACL Analysis"

acl=$(aws_safe s3api get-bucket-acl --bucket "$BUCKET")

if echo "$acl" | grep -qi "AllUsers"; then
    log "🚨 Public ACL detected (AllUsers)"
fi

if echo "$acl" | grep -qi "AuthenticatedUsers"; then
    log "⚠️  AuthenticatedUsers access detected"
fi

# =========================
# Bucket Policy Analysis
# =========================
section "Bucket Policy"

policy=$(aws_safe s3api get-bucket-policy --bucket "$BUCKET")

if [ -n "$policy" ]; then
    echo "$policy" | jq .
    
    if echo "$policy" | grep -qi '"Effect": "Allow".*"Principal": "\*"' ; then
        log "🚨 Public access allowed via policy"
    fi
else
    log "❌ No bucket policy or access denied"
fi

# =========================
# Object Enumeration (single call reused)
# =========================
section "Object Enumeration"

aws_safe s3api list-objects-v2 --bucket "$BUCKET" > "$TMP_FILE"

if [ ! -s "$TMP_FILE" ]; then
    log "❌ Could not list objects"
else
    log "✅ Objects retrieved"
fi

# =========================
# Sensitive Files
# =========================
section "Sensitive Files"

jq -r '
  .Contents[]?
  | select(.Key | test("\\.(sql|bak|backup|env|key|pem|p12|pfx|json|yml|yaml)$"; "i"))
  | "🚨 \(.Key)"
' "$TMP_FILE"

# =========================
# Keyword Search
# =========================
section "Sensitive Keywords"

jq -r '
  .Contents[]?
  | select(.Key | test("(secret|password|token|credential|apikey|private)", "i"))
  | "⚠️  \(.Key)"
' "$TMP_FILE"

# =========================
# Public File Read Test
# =========================
if [ "$PUBLIC" = true ]; then
    section "Public File Read Test"

    jq -r '.Contents[]?.Key' "$TMP_FILE" | head -n $MAX_PUBLIC_CHECK |
    while read -r key; do
        if aws s3 cp "s3://$BUCKET/$key" - --no-sign-request >/dev/null 2>&1; then
            log "🚨 Readable: $key"
        fi
    done
fi

# =========================
# Write Test (safe)
# =========================
section "Write Test"

TEST_FILE="audit-test-$(date +%s).txt"
echo "audit test" > /tmp/$TEST_FILE

if aws_safe s3 cp "/tmp/$TEST_FILE" "s3://$BUCKET/$TEST_FILE"; then
    log "🚨 WRITE access confirmed"

    if aws_safe s3 rm "s3://$BUCKET/$TEST_FILE"; then
        log "⚠️  Cleanup successful (delete allowed)"
    else
        log "⚠️  Could not delete test file"
    fi
else
    log "✅ No write access"
fi

rm -f /tmp/$TEST_FILE "$TMP_FILE"

# =========================
# Done
# =========================
section "Summary"
log "✅ Audit completed for: $BUCKET"