package rules.DEMO_014

import data.snyk

input_type := "tf"

metadata := {
	"id": "DEMO-014",
	"title": "EC2 instance is using an unapproved AMI",
	"severity": "high",
	"description": "We maintain a list of approved AMIs that fit our security and compliance needs. All DemoCorp EC2 instances must use one of these AMIs.",
	"product": ["iac", "cloud"],
	"platform": ["aws"],
}

approved_amis := {
	# us-east-1
	"ami-00c39f71452c08778",
	"ami-02f97949d306b597a",
	# us-east-2
	"ami-04581fbf744a7d11f",
	"ami-0533def491c57d991",
}

test_approved_amis {
	approved_amis["ami-0533def491c57d991"]
}

instances := snyk.resources("aws_instance")

deny[info] {
	instance := instances[_]
	not approved_amis[instance.ami]
	info := {"resource": instance}
}

resources[info] {
	instance := instances[_]
	info := {"resource": instance}
}
