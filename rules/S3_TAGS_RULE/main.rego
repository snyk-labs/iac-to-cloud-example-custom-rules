package rules.S3_TAGS_RULE

import data.snyk

input_type := "tf"

metadata := {
	"id": "S3_TAGS_RULE",
	"title": "All S3 Buckets must be tagged appropriately for identification",
	"severity": "high",
	"description": "All of the S3 Buckets in our environments must have an owner and classification tag",
	"product": ["iac", "cloud"],
	"platform": ["aws"],
}

buckets := snyk.resources("aws_s3_bucket")

owners := {
	"devteam1",
	"devteam2",
	"devteam3",
	"devteam4"
}

classifications := {
	"public",
	"internal",
	"confidential"
}


properly_tagged(bucket) {
	owners[bucket.tags.owner]
	classifications[bucket.tags.classification]
}

deny[info] {
	bucket := buckets[_]
	not properly_tagged(bucket)
	info := {"resource": bucket}
}

resources[info] {
	bucket := buckets[_]
	info := {"resource": bucket}
}
