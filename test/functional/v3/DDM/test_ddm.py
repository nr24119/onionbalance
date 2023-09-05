import base64
import hashlib
import os
import random
import string
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


def get_random_string(length):
    # random string generator
    seq = string.printable
    result_str = ''.join(random.choice(seq) for i in range(length))
    return result_str


class IntroPoint(object):
    # create dummy class for testing, fill with fake data
    identifier = get_random_string(16)


class DummyDesciptor(object):
    # create dummy class for testing, fill with fake data
    intro_points = None
    signing_key = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ"
    inner_layer = "nnDtg7N8kRekv6dw32dRhCheNIBxCEo6JbVci"
    revision_counter = 1346

class TestDDMService(unittest.TestCase):
    intro_points = []
    i = 0
    while i < 8:
        intro_point = IntroPoint()
        intro_points.append(intro_point)
        i += 1

    # fill with fake data
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

        try:
            assert available_space == 49648
        except AssertionError:
            raise

    @mock.patch('onionbalance.hs_v3.service.OnionbalanceService')
    def test_calculate_desc(self, mock_OnionbalanceService):
        """
        test calculation of number of needed descriptors
        """

        available_space = 200
        num_descriptors = OnionbalanceService._calculate_needed_desc(mock_OnionbalanceService, self.intro_points, available_space)
        print(num_descriptors)
        try:
            assert num_descriptors * available_space > len(str(self.intro_points))
        except AssertionError:
            raise

    def test_create_desc(self):
        """
        test assignment of intro points to resp. descriptor
        """
        num_descriptors = 3
        available_intro_points = self.intro_points
        if num_descriptors > 1:
            ddm = True
        else:
            ddm = False

        descriptors = []
        # from here on slightly deviating from actual implementation for simplified testing
        index = len(self.intro_points) // num_descriptors
        i = 0
        while i < num_descriptors:
            assigned_intro_points = []
            j = 0
            while j <= index:
                if len(self.intro_points) > 0:
                    assigned_intro_points.append(self.intro_points[0])
                    self.intro_points.pop(0)
                    print("Assigned intro point %d to (sub)descriptor %d.", j + 1, i + 1)
                else:
                    print("Assigned all intro points to our descriptor(s).")
                j += 1
            try:
                desc = "%s %s %s %d" % (self.onion_address, self.blinding_param, assigned_intro_points,
                                        self.is_first_desc)
            except descriptor.BadDescriptor:
                return
            descriptors.append(desc)
            if ddm:
                print(
                    "Service %s created %s descriptor of subdescriptor %d (%s intro points) (blinding param: %s) "
                    "(size: %s bytes). About to publish:",
                    self.onion_address, "first" if self.is_first_desc else "second", i + 1,
                    len(assigned_intro_points), self.blinding_param, len(str(desc)))
            else:
                print(
                    "Service %s created %s descriptor (%s intro points) (blinding param: %s) "
                    "(size: %s bytes). About to publish:",
                    self.onion_address, "first" if self.is_first_desc else "second",
                    len(assigned_intro_points), self.blinding_param, len(str(desc)))
            i += 1

        print(descriptors)
        try:
            assert(len(self.intro_points) == 0 and len(descriptors) == num_descriptors)
        except AssertionError:
            raise


def test_load_onionbalance():
    service = OnionbalanceService(config_path="/home/laura/Documents/test", service_config_data="config.yaml")

