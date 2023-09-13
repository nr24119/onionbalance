import random
import string
import mock
import unittest
from onionbalance.hs_v3 import descriptor
from onionbalance.hs_v3.service import OnionbalanceService, BadServiceInit


def get_random_string(length):
    # random string generator
    seq = string.printable
    result_str = ''.join(random.choice(seq) for i in range(length))
    return result_str


class DummyIntroPoint(object):
    # create dummy class for testing, fill with fake data
    identifier = get_random_string(16)


class DummyHSdir(object):
    # create dummy class for testing, fill with fake data
    hex_fingerprint = get_random_string(16)


class DummyDesciptor(object):
    # create dummy class for testing, fill with fake data
    intro_points = None
    signing_key = get_random_string(16)
    inner_layer = "nnDtg7N8kRekv6dw32dRhCheNIBxCEo6JbVci"
    revision_counter = 1346
    responsible_hsdirs = None

    def set_responsible_hsdirs(self, responsible_hsdirs):
        self.responsible_hsdirs = responsible_hsdirs


class TestDDMService(unittest.TestCase):
    # fill service with fake intro points, responsible hsdirs and descriptors
    # deviating from actual implementation for testing purposes
    intro_points = []
    responsible_hsdirs = []
    descriptors = []
    i = 0
    while i < 80:
        intro_point = DummyIntroPoint()
        intro_points.append(intro_point)
        i += 1
    j = 0
    while j < 20:
        hsdir = DummyHSdir()
        responsible_hsdirs.append(hsdir)
        j += 1
    z = 0
    while z < 1:
        desc = DummyDesciptor()
        descriptors.append(desc)
        z += 1

    # fill service with fake descriptor data (mimic the first descriptor in descriptor-list)
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
        num_descriptors = OnionbalanceService._calculate_needed_desc(mock_OnionbalanceService, self.intro_points,
                                                                     available_space)
        try:
            assert num_descriptors * available_space > len(str(self.intro_points))
        except AssertionError:
            raise

    def test_create_desc(self):
        """
        test assignment of intro points to resp. descriptor
        number of intro points set in class
        """
        num_descriptors = 6
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
                    break
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

    @mock.patch('onionbalance.hs_v3.service.OnionbalanceService')
    def test_failsafe_param(self, mock_OnionbalanceService):
        # Test with actual implementation
        # default (params.py): HSDIR_N_REPLICAS = 2, HSDIR_SPREAD_STORE = 3
        num_descriptors_a = 1
        num_descriptors_b = 3
        num_descriptors_c = 4
        num_descriptors_d = 8
        failsafe_param_a = OnionbalanceService._load_failsafe_param(mock_OnionbalanceService,
                                                                    num_descriptors=num_descriptors_a)
        failsafe_param_b = OnionbalanceService._load_failsafe_param(mock_OnionbalanceService,
                                                                    num_descriptors=num_descriptors_b)
        failsafe_param_c = OnionbalanceService._load_failsafe_param(mock_OnionbalanceService,
                                                                    num_descriptors=num_descriptors_c)

        try:
            assert failsafe_param_a and failsafe_param_b and not failsafe_param_c
        except AssertionError:
            raise

        try:
            assert failsafe_param_a and failsafe_param_b and not failsafe_param_c
        except AssertionError:
            raise

        self.assertRaises(BadServiceInit, OnionbalanceService._load_failsafe_param, mock_OnionbalanceService,
                     num_descriptors=num_descriptors_d)

    def test_assign_hsdirs(self):
        """
        test assignment of hsdir to our descriptor(s)
        number of hsdirs and descriptors is set in class
        """
        # slightly deviating from actual implementation for simplified testing
        index = len(self.responsible_hsdirs) // len(self.descriptors)
        i = 0
        while i < len(self.descriptors):
            assigned_hsdirs = []
            j = 0
            while j <= index:
                if len(self.responsible_hsdirs) > 0:
                    assigned_hsdirs.append(self.responsible_hsdirs[0])
                    print("Assigned hsdir %s to (sub)descriptor %d.", self.responsible_hsdirs[0], i + 1)
                    self.responsible_hsdirs.pop(0)
                else:
                    print("Assigned all hsdirs to our descriptor(s).")
                    break
                j += 1
            try:
                self.descriptors[i].set_responsible_hsdirs(assigned_hsdirs)
                print("Assigned %d hsdirs to (sub)descriptor %d.", len(self.descriptors[i].responsible_hsdirs), i + 1)
            except BadServiceInit:
                return
            i += 1

        try:
            self.descriptors[0].responsible_hsdirs
        except AssertionError:
            raise


def test_load_onionbalance():
    service = OnionbalanceService(config_path="/home/laura/Documents/test", service_config_data="config.yaml")

