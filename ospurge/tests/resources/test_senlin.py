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
import unittest

import openstack.connection

from ospurge.resources import senlin
from ospurge.tests import mock
from unittest.mock import patch


class TestReceivers(unittest.TestCase):
    def setUp(self):
        self.cloud = mock.Mock(spec_set=openstack.connection.Connection)
        self.creds_manager = mock.Mock(cloud=self.cloud)

    def test_list_with_service(self):
        self.cloud.has_service.return_value = True
        self.assertEqual(
            self.cloud.cluster.
            receivers.return_value,
            senlin.Receivers(self.creds_manager).list()
        )
        self.cloud.has_service.assert_called_once_with('clustering')
        self.cloud.cluster.receivers.assert_called_once_with()

    def test_list_without_service(self):
        self.cloud.has_service.return_value = False
        self.assertEqual(
            [], senlin.Receivers(self.creds_manager).list()
        )
        self.cloud.has_service.assert_called_once_with('clustering')
        self.cloud.cluster.receivers.assert_not_called()

    def test_delete(self):
        receiver = mock.MagicMock()
        self.assertIsNone(senlin.Receivers(self.creds_manager).
                          delete(receiver))
        self.cloud.cluster.delete_receiver.\
            assert_called_once_with(
                receiver['id']
            )

    def test_to_string(self):
        receiver = mock.MagicMock()
        self.assertIn("Receiver (",
                      senlin.Receivers(self.creds_manager).
                      to_str(receiver))


class TestPolicies(unittest.TestCase):
    def setUp(self):
        self.cloud = mock.Mock(spec_set=openstack.connection.Connection)
        self.cluster = mock.MagicMock()
        self.policy = mock.MagicMock()
        self.cloud.cluster.clusters.return_value = [self.cluster]
        self.cloud.cluster.cluster_policies.return_value = [self.policy]
        self.creds_manager = mock.Mock(cloud=self.cloud)
        self.ATTACHED_CLUSTERS = {self.policy['id']: [self.cluster.id]}
        self.policy_obj = senlin.Policies(self.creds_manager)
        self.policy_obj.ATTACHED_CLUSTERS = self.ATTACHED_CLUSTERS

    def test_populate_bindings(self):
        senlin.Policies(self.creds_manager).populate_bindings()
        self.cloud.cluster.clusters.assert_called_once_with()
        self.cloud.cluster.cluster_policies.assert_called_once_with(
            self.cluster.id
        )

    def test_populate_bindings_second_call(self):
        self.policy_obj.populate_bindings()
        self.cloud.cluster.clusters.assert_not_called()
        self.cloud.cluster.cluster_policies.assert_not_called()

    @patch.object(senlin.Policies, 'populate_bindings')
    def test_list_with_service(self, mock_binding):
        self.cloud.has_service.return_value = True
        self.assertEqual(
            self.cloud.cluster.
            policies.return_value,
            senlin.Policies(self.creds_manager).list()
        )
        mock_binding.assert_called_once_with()
        self.cloud.has_service.assert_called_once_with('clustering')
        self.cloud.cluster.policies.assert_called_once_with()

    @patch.object(senlin.Policies, 'populate_bindings')
    def test_list_without_service(self, mock_binding):
        self.cloud.has_service.return_value = False
        self.assertEqual(
            [], senlin.Policies(self.creds_manager).list()
        )
        self.cloud.has_service.assert_called_once_with('clustering')
        mock_binding.assert_not_called()
        self.cloud.cluster.policies.assert_not_called()

    @patch.object(senlin.Policies, 'populate_bindings')
    def test_delete(self, mock_binding):
        self.assertIsNone(self.policy_obj.delete(self.policy))
        self.cloud.detach_policy_from_cluster.\
            assert_called_once_with(
                policy=self.policy['id'],
                cluster=self.cluster.id,
                wait=True
            )
        self.cloud.cluster.delete_policy.assert_called_once_with(
            policy=self.policy['id'])

    def test_disable(self):
        self.assertIsNone(self.policy_obj.disable(self.policy))
        self.cloud.cluster.update_cluster_policy.\
            assert_called_once_with(
                policy=self.policy['id'],
                cluster=self.cluster.id,
                enabled=False
            )

    def test_to_string(self):
        policy = mock.MagicMock()
        self.assertIn("Policy (",
                      senlin.Policies(self.creds_manager).
                      to_str(policy))


class TestClusters(unittest.TestCase):
    def setUp(self):
        self.cloud = mock.Mock(spec_set=openstack.connection.Connection)
        self.creds_manager = mock.Mock(cloud=self.cloud)
        self.spec = {
            'min_size': 0,
            'max_size': 0,
            'adjustment_type': 'EXACT_CAPACITY',
            'number': 0
        }

    def test_check_prerequisite_with_service(self):
        self.cloud.has_service.return_value = True
        self.cloud.cluster.policies.return_value = mock.MagicMock()
        senlin.Clusters(self.creds_manager).check_prerequisite()
        self.cloud.cluster.policies.assert_called_once_with()
        self.cloud.cluster.receivers.assert_called_once_with()
        self.cloud.has_service.assert_called_once_with('clustering')

    def test_check_prerequisite_without_service(self):
        self.cloud.has_service.return_value = False
        senlin.Clusters(self.creds_manager).check_prerequisite()
        self.cloud.cluster.policies.assert_not_called()
        self.cloud.cluster.receivers.assert_not_called()
        self.cloud.has_service.assert_called_once_with('clustering')

    def test_list_with_service(self):
        self.cloud.has_service.return_value = True
        self.assertEqual(
            self.cloud.cluster.
            clusters.return_value,
            senlin.Clusters(self.creds_manager).list()
        )
        self.cloud.has_service.assert_called_once_with('clustering')
        self.cloud.cluster.clusters.assert_called_once_with()

    def test_list_without_service(self):
        self.cloud.has_service.return_value = False
        self.assertEqual(
            [], senlin.Clusters(self.creds_manager).list()
        )
        self.cloud.has_service.assert_called_once_with('clustering')
        self.cloud.cluster.clusters.assert_not_called()

    def test_delete(self):
        cluster = mock.MagicMock()
        self.assertIsNone(senlin.Clusters(self.creds_manager).
                          delete(cluster))
        self.cloud.cluster.delete_cluster.\
            assert_called_once_with(
                cluster=cluster['id']
            )

    def test_disable(self):
        cluster = mock.MagicMock()
        self.assertIsNone(senlin.Clusters(self.creds_manager).
                          disable(cluster))
        self.cloud.cluster.resize_cluster.\
            assert_called_once_with(
                cluster=cluster['id'],
                **self.spec
            )

    def test_to_string(self):
        cluster = mock.MagicMock()
        self.assertIn("Cluster (",
                      senlin.Clusters(self.creds_manager).
                      to_str(cluster))


class TestProfiles(unittest.TestCase):
    def setUp(self):
        self.cloud = mock.Mock(spec_set=openstack.connection.Connection)
        self.creds_manager = mock.Mock(cloud=self.cloud)

    def test_check_prerequisite_with_service(self):
        self.cloud.has_service.return_value = True
        self.cloud.cluster.clusters.return_value = mock.MagicMock()
        senlin.Profiles(self.creds_manager).check_prerequisite()
        self.cloud.cluster.clusters.assert_called_once_with()
        self.cloud.has_service.assert_called_once_with('clustering')

    def test_check_prerequisite_without_service(self):
        self.cloud.has_service.return_value = False
        senlin.Profiles(self.creds_manager).check_prerequisite()
        self.cloud.cluster.clusters.assert_not_called()
        self.cloud.has_service.assert_called_once_with('clustering')

    def test_list_with_service(self):
        self.cloud.has_service.return_value = True
        self.assertEqual(
            self.cloud.cluster.
            profiles.return_value,
            senlin.Profiles(self.creds_manager).list()
        )
        self.cloud.has_service.assert_called_once_with('clustering')
        self.cloud.cluster.profiles.assert_called_once_with()

    def test_list_without_service(self):
        self.cloud.has_service.return_value = False
        self.assertEqual(
            [], senlin.Profiles(self.creds_manager).list()
        )
        self.cloud.has_service.assert_called_once_with('clustering')
        self.cloud.cluster.profiles.assert_not_called()

    def test_delete(self):
        profile = mock.MagicMock()
        self.assertIsNone(senlin.Profiles(self.creds_manager).
                          delete(profile))
        self.cloud.cluster.delete_profile.\
            assert_called_once_with(
                profile=profile['id']
            )

    def test_disable(self):
        profile = mock.MagicMock()
        with self.assertLogs(level='WARNING'):
            senlin.Profiles(self.creds_manager).disable(profile)

    def test_to_string(self):
        profile = mock.MagicMock()
        self.assertIn("Profile (",
                      senlin.Profiles(self.creds_manager).
                      to_str(profile))
