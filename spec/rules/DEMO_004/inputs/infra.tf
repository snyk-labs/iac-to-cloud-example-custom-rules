resource "github_repository" "valid_by_node_id" {
  name = "valid-by-node-id"
}

resource "github_branch_protection" "valid_by_node_id" {
  repository_id = github_repository.valid_by_node_id.node_id
  pattern       = "main"

  required_status_checks {}
}

resource "github_repository" "valid_by_name" {
  name = "valid-by-name"
}

resource "github_branch_protection" "valid_by_name" {
  repository_id = github_repository.valid_by_name.name
  pattern       = "main"

  required_status_checks {}
}

resource "github_repository" "invalid" {
  name = "invalid"
}

resource "github_repository" "invalid_missing_block" {
  name = "invalid-missing-block"
}

resource "github_branch_protection" "invalid_missing_block" {
  repository_id = github_repository.invalid_missing_block.name
  pattern       = "main"
}
