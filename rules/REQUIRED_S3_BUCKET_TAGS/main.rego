 # © 2023 Snyk Limited
 #
 # Licensed under the Apache License, Version 2.0 (the "License");
 # you may not use this file except in compliance with the License.
 # You may obtain a copy of the License at
 #
 #     http://www.apache.org/licenses/LICENSE-2.0
 #
 # Unless required by applicable law or agreed to in writing, software
 # distributed under the License is distributed on an "AS IS" BASIS,
 # WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 # See the License for the specific language governing permissions and
 # limitations under the License.

package rules.REQUIRED_S3_BUCKET_TAGS

import data.snyk

input_type := "tf"

metadata := {
	"id": "REQUIRED_S3_BUCKET_TAGS",
	"severity": "high",
	"title": "S3 Bucket Tags",
	"description": "All S3 Buckets must be tagged properly - they need to have an owner tag, and a classification tag with the proper values.",
	"product": [
		"iac",
		"cloud",
	],
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
