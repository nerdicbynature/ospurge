#  Licensed under the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License. You may obtain
#  a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#  License for the specific language governing permissions and limitations
#  under the License.
from ospurge.resources import base


class Receivers(base.ServiceResource):
    ORDER = 99

    def list(self):
        if not self.cloud.has_service('clustering'):
            return []
        return self.cloud.cluster.receivers()

    def delete(self, resource):
        self.cloud.cluster.delete_receiver(resource['id'])

    @staticmethod
    def to_str(resource):
        return "Receiver (id='{}', name='{}')".format(
            resource['id'], resource['name'])


class Policies(base.ServiceResource):
    ORDER = 100
    ATTACHED_CLUSTERS = None

    def __init__(self, creds_manager):
        self.ATTACHED_CLUSTERS = {}
        super(Policies, self).__init__(creds_manager)

    def populate_bindings(self):
        if self.ATTACHED_CLUSTERS:
            return

        for cluster in self.cloud.cluster.clusters():
            for policy in self.cloud.cluster.cluster_policies(cluster.id):
                self.append_to_attached_clusters(policy, cluster)

    def append_to_attached_clusters(self, policy, cluster):
        if policy.policy_id not in self.ATTACHED_CLUSTERS:
            self.ATTACHED_CLUSTERS[policy.policy_id] = []
        self.ATTACHED_CLUSTERS[policy.policy_id].append(cluster.id)

    def list(self):
        if not self.cloud.has_service('clustering'):
            return []
        # populate the bindings of the policies
        self.populate_bindings()
        return self.cloud.cluster.policies()

    def delete(self, resource):
        policy_attached_clusters = self.ATTACHED_CLUSTERS.get(
            resource['id'], [])
        for attached_cluster_id in policy_attached_clusters:
            self.cloud.detach_policy_from_cluster(
                cluster=attached_cluster_id,
                policy=resource['id'],
                wait=True
            )

        self.cloud.cluster.delete_policy(policy=resource['id'])

    def disable(self, resource):
        policy_attached_clusters = self.ATTACHED_CLUSTERS.get(
            resource['id'], [])
        for attached_cluster_id in policy_attached_clusters:
            self.cloud.cluster.update_cluster_policy(
                cluster=attached_cluster_id,
                policy=resource['id'],
                enabled=False
            )

    @staticmethod
    def to_str(resource):
        return "Policy (id='{}', name='{}')".format(
            resource['id'], resource['name'])


class Clusters(base.ServiceResource):
    ORDER = 101
    SPEC = {
        'min_size': 0,
        'max_size': 0,
        'adjustment_type': 'EXACT_CAPACITY',
        'number': 0
    }

    def check_prerequisite(self):
        if not self.cloud.has_service('clustering'):
            return True
        # We can't delete till policies, receivers are deleted
        policy_list_gen = self.cloud.cluster.policies()
        receiver_list_gen = self.cloud.cluster.receivers()
        return next(policy_list_gen, None) is None and \
            next(receiver_list_gen, None) is None

    def list(self):
        if not self.cloud.has_service('clustering'):
            return []
        return self.cloud.cluster.clusters()

    def delete(self, resource):
        self.cloud.cluster.delete_cluster(cluster=resource['id'])

    def disable(self, resource):
        self.cloud.cluster.resize_cluster(
            cluster=resource['id'],
            **Clusters.SPEC
        )

    @staticmethod
    def to_str(resource):
        return "Cluster (id='{}', name='{}')".format(
            resource['id'], resource['name'])


class Profiles(base.ServiceResource):
    ORDER = 103

    def check_prerequisite(self):
        if not self.cloud.has_service('clustering'):
            return True
        # Check all clusters are deleted
        list_gen = self.cloud.cluster.clusters()
        return next(list_gen, None) is None

    def list(self):
        if not self.cloud.has_service('clustering'):
            return []
        return self.cloud.cluster.profiles()

    def delete(self, resource):
        self.cloud.cluster.delete_profile(profile=resource['id'])

    @staticmethod
    def to_str(resource):
        return "Profile (id='{}', name='{}')".format(
            resource['id'], resource['name'])
