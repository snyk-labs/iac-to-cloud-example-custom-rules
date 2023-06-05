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

# Utilities for rule testing.
package lib.rule_tests

resource_id(resource) = ret {
	ret := resource._meta.tfruntime.key
} else = ret {
	ret := sprintf("%s.%s", [resource._type, resource._meta.tfstate.name])
} else = ret {
	ret := resource._id
}

correlation_id(info) = ret {
	ret := info.correlation
} else = ret {
	ret := resource_id(info.primary_resource)
} else = ret {
	ret := resource_id(info.resource)
}

# Handle missing resources

else = ret {
	ret := info.resource_type
}

# Groups info objects by resource ID.
# Removes the resource so useful comparisons can be done.
by_correlation_id(infos) = ret {
	ret := {id: infos_without_resource |
		some i
		infos[i]
		id := correlation_id(i)
		infos_without_resource := {info_without_resource |
			some j
			correlation_id(infos[j]) == id
			patches := array.concat(
				[p | p := {"op": "replace", "path": ["resource"], "value": resource_id(j.resource)}],
				array.concat(
					[p | p := {"op": "remove", "path": ["primary_resource"]}; j.primary_resource],
					[p | p := {"op": "remove", "path": ["correlation_id"]}; j.correlation_id],
				),
			)

			info_without_resource := json.patch(j, patches)
		}
	}
}

# Sets up a stub resource set that the test implementation of query() will
# return when called with the specified resource query, but only if no such
# resources are found in the input by resources().
query_returns(protoInput, resourceQuery, resources) = ret {
	resourceQueryStr := json.marshal(resourceQuery)
	ret := object.union(protoInput, {"_query": {resourceQueryStr: resources}})
}

# A helper for creating nice snapshots on `deny` and `resources`.
snapshot_deny_resources(deny, resources) = ret {
	ret := {
		"deny": by_correlation_id(deny),
		"resources": by_correlation_id(resources),
	}
}
