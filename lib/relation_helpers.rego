package relation_helpers

import data.snyk

relation_from_fields(name, left, right) = info {
	info := {
		"name": name,
		"keys": {
			"left": [[resource, resource[field]] |
				fields := left[resource_type]
				resource := snyk.resources(resource_type)[_]
				field := fields[_]
			],
			"right": [[resource, resource[field]] |
				fields := right[resource_type]
				resource := snyk.resources(resource_type)[_]
				field := fields[_]
			],
		},
	}
}
