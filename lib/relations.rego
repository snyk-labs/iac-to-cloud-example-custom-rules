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

package relations

import data.relation_helpers

relations[info] {
	info := relation_helpers.relation_from_fields(
		"github_repository.branch_protection",
		{"github_repository": ["name", "id", "node_id"]},
		{"github_branch_protection": ["repository_id"]},
	)
}
