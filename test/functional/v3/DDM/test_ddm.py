import base64
import hashlib
import os
import struct

import mock
import unittest

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from onionbalance.hs_v3 import descriptor
from onionbalance.hs_v3.service import OnionbalanceService, BadServiceInit


class DummyService(object):
    def __init__(self):
        self.instances = []

class TestDDMService(unittest.TestCase):
    intro_points = [
        "D1D1D1D1D1D1D1D1D1D1D1D1D1D1D1D1D1D1D1D1",
        "2F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2F",
        "B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0",
        "3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A",
        "5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A",
        "DFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDF",
        "F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7",
        "3434343434343434343434343434343434343434"]

    blinding_param = "3434343434343434343434343434343434343434"
    is_first_desc = True
    onion_address = 'bvy46sg2b5dokczabwv2pabqlrps3lppweyrebhat6gjieo2avojdvad.onion'

    @mock.patch('onionbalance.hs_v3.service.OnionbalanceService')
    def test_calculate_space(self, mock_OnionbalanceService):
        """
        test calculation of available space per descriptor
        """
        empty_desc = [
        "D1D1D1D1D1D1D1D1D1D1D1D1D1D1D1D1D1D1D1D1",
        "2F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2F",
        "B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0",
        "3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A",
        "5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A",
        "DFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDFDF",
        "F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7",
        "3434343434343434343434343434343434343434" ]
        available_space = OnionbalanceService._calculate_space(mock_OnionbalanceService, empty_desc)
        print(available_space)
        assert available_space == 49648

    @mock.patch('onionbalance.hs_v3.service.OnionbalanceService')
    def test_calculate_desc(self, mock_OnionbalanceService):
        """
        test calculation of number of needed descriptors
        """

        available_space = 200

        num_descriptors = OnionbalanceService._calculate_needed_desc(mock_OnionbalanceService, self.intro_points, available_space)
        print(num_descriptors)

        assert num_descriptors*available_space > len(str(self.intro_points))

    @mock.patch('onionbalance.hs_v3.service.OnionbalanceService')
    def test_assign_desc(self, mock_OnionbalanceService):
        """
        test assignment of intro points to resp. descriptor
        """
        num_descriptors = 2
        if num_descriptors > 1:
            ddm = True
        else:
            ddm = False

        descriptors = []

        i = 0
        while i < num_descriptors:
            assigned_intro_points = OnionbalanceService._assign_intro_points(mock_OnionbalanceService, self.intro_points, num_descriptors)
            desc = OnionbalanceService._create_descriptor(mock_OnionbalanceService, assigned_intro_points, self.blinding_param, self.is_first_desc)
            descriptors.append(desc)
            if ddm:
                print(
                    "Service %s created %s descriptor of subdescriptor %d (%s intro points) (blinding param: %s) "
                    "(size: %s bytes). About to publish:",
                    self.onion_address, "first" if self.is_first_desc else "second", i + 1,
                    len(desc.intro_set), self.blinding_param.hex(), len(str(desc.v3_desc)))
            else:
                print(
                    "Service %s created %s descriptor (%s intro points) (blinding param: %s) "
                    "(size: %s bytes). About to publish:",
                    self.onion_address, "first" if self.is_first_desc else "second",
                    len(desc.intro_set), self.blinding_param.hex(), len(str(desc.v3_desc)))
                while len(assigned_intro_points) > 0:
                    self.intro_points.remove(assigned_intro_points)
            i += 1

def test_load_onionbalance():
    service = OnionbalanceService(config_path="/home/laura/Documents/test", service_config_data="config.yaml")

