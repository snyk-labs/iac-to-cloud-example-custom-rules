package rules.TAG_EXCEPTION

import data.snyk

input_type := "tf"

metadata := {
	"id": "TAG_EXCEPTION",
	"title": "Specific buckets can be public if tagged properly",
	"severity": "high",
	"description": "If an S3 bucket has the proper tags, it can be public. It must have 'allowedPublic:yes' key and value",
	"product": ["iac", "cloud"],
	"platform": ["aws"],
}

buckets := snyk.resources("aws_s3_bucket")
blocks := snyk.resource("aws_s3_bucket_public_access_block")

is_acceptable(bucket) {
	block = blocks[_]
	bucket.bucket == block.bucket
	block.block_public_acls == true
  block.ignore_public_acls == true
  block.block_public_policy == true
  block.restrict_public_buckets == true
}

is_acceptable(bucket) {
	bucket.tags.allowedPublic == "yes"
}

deny[info] {
	bucket := buckets[_]
	not is_acceptable(bucket)
	info := {"resource": bucket}
}

resources[info] {
	bucket := buckets[_]
	block := snyk.relates(bucket, "aws_s3_block_public_access_block")[_]
  info := {
    "primary_resource": bucket,
    "resource": block, 
  }
}
