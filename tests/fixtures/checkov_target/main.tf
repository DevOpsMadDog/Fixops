# ALdeci test fixture for config_benchmark_engine checkov integration tests.
# This file is intentionally mixed: some checks pass, some fail.
# DO NOT make this file "secure" — tests assert failed_checks > 0.

# INSECURE: public-read ACL, no encryption, no versioning, no logging
resource "aws_s3_bucket" "insecure_bucket" {
  bucket = "aldeci-test-insecure-bucket"
  acl    = "public-read"
}

# SECURE-ish: private bucket with encryption enabled
resource "aws_s3_bucket" "secure_bucket" {
  bucket = "aldeci-test-secure-bucket"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "secure_bucket_sse" {
  bucket = aws_s3_bucket.secure_bucket.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "secure_bucket_versioning" {
  bucket = aws_s3_bucket.secure_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}
