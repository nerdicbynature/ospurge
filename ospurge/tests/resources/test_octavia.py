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
import uuid

import openstack.connection

from ospurge.resources import octavia
from ospurge.tests import mock


class TestLoadBalancers(unittest.TestCase):
    def setUp(self):
        self.cloud = mock.Mock(spec_set=openstack.connection.Connection)
        self.creds_manager = mock.Mock(cloud=self.cloud)

    def test_list_without_service(self):
        self.cloud.has_service.return_value = False
        self.assertEqual(octavia.LoadBalancers(self.creds_manager).list(), [])
        self.cloud.load_balancer.load_balancers.assert_not_called()

    def test_list_with_service(self):
        self.cloud.has_service.return_value = True
        my_project = str(uuid.uuid4())
        self.creds_manager.project_id = my_project
        self.assertIs(
            self.cloud.load_balancer.load_balancers.return_value,
            octavia.LoadBalancers(self.creds_manager).list())
        self.cloud.load_balancer.load_balancers.assert_called_once_with(
            project_id=my_project)

    def test_delete(self):
        lb = mock.MagicMock()
        self.assertIsNone(octavia.LoadBalancers(self.creds_manager).delete(lb))
        (self.cloud.load_balancer.delete_load_balancer
         .assert_called_once_with(lb['id'], cascade=True))

    def test_disable(self):
        lb = mock.MagicMock()
        self.assertIsNone(octavia.LoadBalancers(self.creds_manager).disable(
            lb))
        (self.cloud.load_balancer.update_load_balancer
         .assert_called_once_with(lb['id'], admin_state_up=False))

    def test_to_string(self):
        stack = mock.MagicMock()
        self.assertIn("Octavia LoadBalancer",
                      octavia.LoadBalancers(self.creds_manager).to_str(stack))
