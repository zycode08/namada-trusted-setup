#!/bin/bash -e

# Run the coordinator and e2e tests against a remote S3 bucket. Clean the bucket before each test.

# Check credentials
for cred in "$AWS_ACCESS_KEY_ID" "$AWS_SECRET_ACCESS_KEY" "$AWS_S3_BUCKET"; do
    if [ -z $cred ]; then
        echo "Credentials env variables must be set!"
        exit 1
    fi
done

# Coordinator test
echo "Cleaning S3 bucket for coordinator test..."
aws s3 rm s3://trusted-setup-artifacts-local-v1 --recursive
cargo test --test test_coordinator -- --test-threads=1

# e2e test
# FIXME: uncomment this block after having fixed e2e tests
# echo "Cleaning S3 bucket for e2e test..."
# aws s3 rm s3://trusted-setup-artifacts-local-v1 --recursive
# cargo test --test e2e -- --test-threads=1
