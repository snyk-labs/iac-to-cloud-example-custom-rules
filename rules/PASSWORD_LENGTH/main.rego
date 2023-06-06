package rules.PASSWORD_LENGTH

import data.snyk

input_type := "tf"

metadata := {
	"id": "PASSWORD LENGTH",
	"title": "Minimum user password length must be 15 characters long",
	"severity": "high",
	"description": "All User passwords must be a minimum of 15 characters long",
	"product": ["iac", "cloud"],
	"platform": ["aws"],
}

password_pols = snyk.resources("iam_account_password_policy")

deny[info] {
	password_pol := password_pols[_]
	password_pol.minimum_password_length < 15
	info := {"resource": password_pol}
}

resources[info] {
	password_pol := password_pols[_]
	info := {"resource": password_pol}
}
