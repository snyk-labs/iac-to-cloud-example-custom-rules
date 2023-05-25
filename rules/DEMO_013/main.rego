package rules.DEMO_013

import data.snyk

resource_type := "MULTIPLE"

input_type := "tf"

metadata := {
	"id": "DEMO-013",
	"title": "Default branch should restrict who can push to it",
	"severity": "low",
	"description": "By default, commits can be pushed directly to protected branches without going through a Pull Request. Restrict who can push commits to protected branches so that commits can be added only via merges, which require Pull Request.",
	"product": ["iac"],
}

repos := snyk.resources("github_repository")

is_valid(repo) {
	branch_protection := snyk.relates(repo, "github_repository.branch_protection")[_]
	count(branch_protection.push_restrictions) > 0
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
