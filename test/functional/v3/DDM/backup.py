import binascii
import hashlib

import pexpect
import sys
import time

import self
from cryptography.hazmat.primitives import serialization
from mock import mock


from onionbalance.hs_v3 import onionbalance, descriptor, tor_ed25519
from onionbalance.hs_v3.consensus import Consensus
from onionbalance.hs_v3.onionbalance import Onionbalance, ConfigError, my_onionbalance
from onionbalance.hs_v3.service import OnionbalanceService
from test.functional.util import *
from test.functional.util import create_test_config_file_v3
from test.v3.test_v3_keys import PRIVKEY_FILE_HEX
from test.v3.test_v3_onionbalance import DummyConsensus
from test.v3.test_v3_status import DummyService

import onionbalance
from onionbalance.hs_v3 import manager
from onionbalance.common import argparser
from onionbalance.common import manager as common_manager

PUBKEY_STRING = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
PUBKEY = bytes.fromhex(PUBKEY_STRING)
PREFIX = ".onion checksum".encode()
VERSION = 3
data = struct.pack('15s32sb', PREFIX, PUBKEY, VERSION)
checksum = hashlib.sha3_256(data).digest()
address = struct.pack('!32s2sb', PUBKEY, checksum, VERSION)
onion_address = base64.b32encode(address).decode().lower()
blinding_param = '54a513898b471d1d448a2f3c55c1de2c0ef718c447b04497eeb999ed32027823'
empty_intro_points = []
key_fname = "/home/laura/Documents/test/tjoy5nhvtspgmjn7uhlt57qkcpyyi4qhmo44v3hahi6th427eaaga5qd.key"
try:
    with open(key_fname, 'rb') as handle:
        pem_key_bytes = handle.read()
except EnvironmentError as e:
    raise BadServiceInit
identity_priv_key = serialization.load_pem_private_key(pem_key_bytes, password=None, backend=default_backend())

empty_desc = descriptor.OBDescriptor(onion_address, identity_priv_key,
                                     blinding_param, empty_intro_points, True)
print(empty_desc)

def test_loadup():
    parser = onionbalance.common.argpaser.get_common_argparser()
    common_manager.main()

    parser = argparser.get_common_argparser()
    args = parser.parse_args()
    args = argparser.parse_args('/usr/sbin/onionbalance', '--hs-version', 'v3', '-i', '127.0.0.1', '-p', '8008', '-c',
                                '/tmp/pytest-of-laura/pytest-1/test_sighup_reload_config0/config.yaml', '-v', 'debug',
                                '--is-testnet')
    manager.main(args)
class DummyOnionbalance:
    def __init__(self):
        self.consensus = DummyConsensus

class DummyConsensus:
    def __init__(self):
        self.get_time_period_length = 20


def test_calculate_space(tmpdir, num_instances=3):
    service = DummyService()
    consensus = DummyConsensus()


    onion_address='w2krcw62j7l5h7fcftgz2zopwemdt2lbqlpj43ikkpinpy6wcifok4ad.onion'
    privkey_bytes = binascii.unhexlify(PRIVKEY_FILE_HEX)
    privkey = tor_ed25519.load_tor_key_from_disk(privkey_bytes)
    pubkey = privkey.public_key()
    identity_pubkey = pubkey.public_bytes(encoding=serialization.Encoding.Raw,
                                  format=serialization.PublicFormat.Raw)
    ED25519_BASEPOINT = b"(15112221349535400772501151409588531511" \
                        b"454012693041857206046113283949847762202, " \
                        b"463168356949264781694283940034751631413" \
                        b"07993866256225615783033603165251855960)"
    BLIND_STRING = b"Derive temporary signing key" + bytes([0])

    period_length = consensus.get_time_period_length()
    time_period_number = 12
    N = b"key-blind" + time_period_number.to_bytes(8, 'big') + period_length.to_bytes(8, 'big')

    blinding_param = hashlib.sha3_256(BLIND_STRING + identity_pubkey + ED25519_BASEPOINT + N).digest()
    #blinding_param = consensus.get_blinding_param(privkey.public_bytes(encoding=serialization.Encoding.Raw,
    #                                         format=serialization.PublicFormat.Raw), 1)
    instances = {}

    test_onionbalance = DummyOnionbalance()
    empty_desc = descriptor.OBDescriptor(onion_address, privkey, blinding_param, instances, True)
    print(empty_desc)






    key_fname = config_data['services']['key']
    identity_priv_key = serialization.load_pem_private_key(key_fname, password=None, backend=default_backend())
    onion_address = config_data['address']
    identity_pub_key = identity_priv_key.public_key()
    blinding_param = my_onionbalance.consensus.get_blinding_param(identity_pub_key.public_bytes(encoding=serialization.Encoding.Raw,
                                             format=serialization.PublicFormat.Raw), 1)
    empty_intro_points = []
    try:
        empty_desc = descriptor.OBDescriptor(onion_address, identity_priv_key,
                                             blinding_param, empty_intro_points, is_first_desc)
    except descriptor.BadDescriptor:
        return




    service = OnionbalanceService(config_data, config_file_path)
    service.first_descriptor = None
    service.second_descriptor = None
    my_onionbalance.services = [service]
    print(service)



    available_space = service._calculate_space(empty_desc)
    print(available_space)


def test_to_many_instances(self, tmpdir, num_instances=300):
    """
    tests if ConfigError is thrown when there are too many instances in the config file
    """
    # run Chutney net and set Chutney environment manually - because reading from OS environment didn't work
    os.environ['CHUTNEY_ONION_ADDRESS'] = 'w2krcw62j7l5h7fcftgz2zopwemdt2lbqlpj43ikkpinpy6wcifok4ad.onion:5858'
    os.environ['CHUTNEY_CLIENT_PORT'] = 'localhost:9008'

    chutney_config = parse_chutney_environment()

    list_instances = []
    i = 0
    while i < num_instances:
        list_instances.append(random_onionv3_address())
        i += 1

    config_file_path = create_test_config_file_v3(tmppath=tmpdir, instance_address=list_instances,
                                                  num_instances=num_instances)
    assert config_file_path

    server = pexpect.spawn("onionbalance",
                           args=[
                               '--hs-version', 'v3',
                               '-i', chutney_config.get('client_ip'),
                               '-p', str(chutney_config.get('control_port')),
                               '-c', config_file_path,
                               '-v', 'debug',
                               '--is-testnet'
                           ], logfile=sys.stdout.buffer, timeout=5)
    time.sleep(1)

    test_onionbalance = Onionbalance()
    test_onionbalance.config_path = config_file_path
    onionbalance.Onionbalance.load_config_file(test_onionbalance)

    self.assertRaises(ConfigError)