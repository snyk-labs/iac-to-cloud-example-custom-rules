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

package rules.S3_ACL

import data.snyk

input_type := "tf"

metadata := {
	"id": "S3_BUCKET_ACL",
	"severity": "critical",
	"title": "All ACLs should be private",
	"description": "Checking S3 Buckets for Private ACLs using the new terraform format.",
	"product": [
		"iac",
		"cloud",
	],
}

buckets := snyk.resources("aws_s3_bucket")

deny[info] {
	bucket := buckets[_]
	acls := snyk.relates(bucket, "aws_s3_bucket.aws_s3_bucket_acl")
	acl := acls[_]
	acl.acl != "private"
	info := {"primary_resource": bucket}

}

resources[info] {
	bucket := buckets[_]
	info := {"primary_resource": bucket}
}

resources[info] {
	bucket := buckets[_]
	acls := snyk.relates(bucket, "aws_s3_bucket.aws_s3_bucket_acl")
	info := {
		"primary_resource": bucket,
		"resource": acls[_],
	}
}
