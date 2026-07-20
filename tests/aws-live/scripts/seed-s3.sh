#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib.sh"

BLUEARCH_STEWARD_LIVE_PREFIX="${BLUEARCH_STEWARD_LIVE_PREFIX:-$(new_live_prefix)}"
export BLUEARCH_STEWARD_LIVE_PREFIX
write_live_env "$BLUEARCH_STEWARD_LIVE_PREFIX"

PUBLIC_BUCKET="$(fixture_bucket public)"
UNENCRYPTED_BUCKET="$(fixture_bucket unencrypted)"
NO_LIFECYCLE_BUCKET="$(fixture_bucket no-lifecycle)"
VERSIONING_DISABLED_BUCKET="$(fixture_bucket versioning-disabled)"
SECURE_BUCKET="$(fixture_bucket secure)"

for bucket in "$PUBLIC_BUCKET" "$UNENCRYPTED_BUCKET" "$NO_LIFECYCLE_BUCKET" "$VERSIONING_DISABLED_BUCKET" "$SECURE_BUCKET"; do
  reset_bucket_to_empty_baseline "$bucket"
done

# Public bucket: empty bucket, public policy, and bucket-level public access block disabled.
disable_public_access_block "$PUBLIC_BUCKET"
enable_default_encryption "$PUBLIC_BUCKET"
enable_lifecycle "$PUBLIC_BUCKET"
enable_versioning "$PUBLIC_BUCKET"

public_policy_file="$(mktemp)"
cat > "$public_policy_file" <<JSON
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "BlueArchLivePublicReadFixture",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::$PUBLIC_BUCKET/*"
    }
  ]
}
JSON
if ! "${AWS_CMD[@]}" s3api put-bucket-policy --bucket "$PUBLIC_BUCKET" --policy "file://$public_policy_file" >/dev/null 2>"$ARTIFACT_DIR/public-policy-error.txt"; then
  echo "Warning: public bucket policy fixture was blocked by AWS account controls. See $ARTIFACT_DIR/public-policy-error.txt" >&2
fi
rm -f "$public_policy_file"

# Unencrypted bucket: missing explicit default bucket encryption configuration where AWS permits it.
enable_public_access_block "$UNENCRYPTED_BUCKET"
disable_default_encryption "$UNENCRYPTED_BUCKET"
enable_lifecycle "$UNENCRYPTED_BUCKET"
enable_versioning "$UNENCRYPTED_BUCKET"

# No lifecycle bucket.
enable_public_access_block "$NO_LIFECYCLE_BUCKET"
enable_default_encryption "$NO_LIFECYCLE_BUCKET"
disable_lifecycle "$NO_LIFECYCLE_BUCKET"
enable_versioning "$NO_LIFECYCLE_BUCKET"

# Versioning disabled bucket.
enable_public_access_block "$VERSIONING_DISABLED_BUCKET"
enable_default_encryption "$VERSIONING_DISABLED_BUCKET"
enable_lifecycle "$VERSIONING_DISABLED_BUCKET"
disable_versioning "$VERSIONING_DISABLED_BUCKET"

# Secure control bucket.
enable_public_access_block "$SECURE_BUCKET"
enable_default_encryption "$SECURE_BUCKET"
enable_lifecycle "$SECURE_BUCKET"
enable_versioning "$SECURE_BUCKET"

echo "Seeded AWS live S3 fixture prefix: $BLUEARCH_STEWARD_LIVE_PREFIX"
printf '  - s3://%s\n' "$PUBLIC_BUCKET" "$UNENCRYPTED_BUCKET" "$NO_LIFECYCLE_BUCKET" "$VERSIONING_DISABLED_BUCKET" "$SECURE_BUCKET"

