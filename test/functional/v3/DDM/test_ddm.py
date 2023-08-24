import unittest

import pexpect
import sys
import time
from onionbalance.hs_v3 import onionbalance
from onionbalance.hs_v3.onionbalance import Onionbalance, ConfigError
from test.functional.util import *
from test.functional.util import create_test_config_file_v3


class DDMTestCase(unittest.TestCase):
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