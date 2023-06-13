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

package rules.VPC_FLOW_LOG_EXCEPTION

import data.snyk

input_type := "tf"

metadata := {
	"id": "VPC_FLOW_LOG_EXCEPTION",
	"severity": "high",
	"title": "VPC Flow Log Exception based on tag",
	"description": "All VPCs must have flow logs unless they have a specific key value pair - this rule modifies SNYK-CC-00151 to exclude a vpc based on its tags",
	"product": [
		"iac",
		"cloud",
	],
}

vpcs := snyk.resources("aws_vpc")

acceptable_vpcs(vpc) {
	vpc.tags.name == "cloudbank-fix"
}

acceptable_vpcs(vpc) {
	logs := snyk.relates(vpc, "aws_vpc.aws_flow_log")[_]
	count(logs) < 0
}

deny[info] {
	vpc := vpcs[_]
	not acceptable_vpcs(vpc)

	info := {"primary_resource": vpc}
}

resources[info] {
	vpc := vpcs[_]
	info := {"primary_resource": vpc}
}

resources[info] {
	vpc := vpcs[_]
	logs := snyk.relates(vpc, "aws_vpc.aws_flow_log")
	info := {
		"primary_resource": vpc,
		"resource": logs[_],
	}
}
