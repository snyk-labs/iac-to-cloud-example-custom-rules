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

package rules.DEMO_007

import data.snyk

resource_type := "MULTIPLE"

input_type := "tf"

metadata := {
	"id": "DEMO-007",
	"title": "Default branch should require branches to be up to date before merge",
	"severity": "medium",
	"description": "Branches that are not up to date can be merged. This can result in previously remediated issues being merged in over fixes.",
	"product": ["iac"],
}

repos := snyk.resources("github_repository")

is_valid(repo) {
	branch_protection := snyk.relates(repo, "github_repository.branch_protection")[_]
	branch_protection.required_status_checks[_].strict == true
}

deny[info] {
	repo := repos[_]
	not is_valid(repo)
	info := {"resource": repo}
}

resources[info] {
	repo := repos[_]
	info := {"resource": repo}
}

resources[info] {
	repo := repos[_]
	branch_protection := snyk.relates(repo, "github_repository.branch_protection")[_]
	info := {
		"primary_resource": repo,
		"resource": branch_protection,
	}
}
