package relations

import data.relation_helpers

relations[info] {
	info := relation_helpers.relation_from_fields(
		"github_repository.branch_protection",
		{"github_repository": ["name", "id", "node_id"]},
		{"github_branch_protection": ["repository_id"]},
	)
}
