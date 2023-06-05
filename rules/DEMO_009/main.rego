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

package rules.DEMO_009

import data.snyk

resource_type := "MULTIPLE"

input_type := "tf"

metadata := {
	"id": "DEMO-009",
	"title": "Default branch should require code review by at least two reviewers",
	"severity": "medium",
	"description": "In order to comply with separation of duties principle and enforce secure code practices, a code review should be mandatory using the source-code-management built-in enforcement. This option is found in the branch protection setting of the repository.",
	"product": ["iac"],
}

repos := snyk.resources("github_repository")

is_valid(repo) {
	branch_protection := snyk.relates(repo, "github_repository.branch_protection")[_]
	branch_protection.required_pull_request_reviews[_].required_approving_review_count >= 2
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
