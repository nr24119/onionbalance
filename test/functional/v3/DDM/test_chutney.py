# -*- coding: utf-8 -*-
import signal
import sys
import time

import pexpect

from test.functional.util import *

def test_chutney(tmpdir, num_instances = 30):
    """
    Functional test to run Onionbalance with Distinct Descriptor Mode, send SIGHUP then check if config is reloaded
    """

    # run Chutney net and set Chutney environment manually - because reading from OS environment didn't work
    os.environ['CHUTNEY_ONION_ADDRESS'] = 'gpazawwakaznnixgwe6xdlb3bm4rnrroaivavw4gz324tq4ibiccgayd.onion:5858'
    os.environ['CHUTNEY_CLIENT_PORT'] = 'localhost:9008'

    # collect all instances (onion addresses) from current chutney net (/chutney/net/nodes.169...):
    # cat */hidden_service/hostname > /home/laura/Documents/all.txt
    # set path to file here
    instances_path = "/home/laura/Documents/all.txt"

    chutney_config = parse_chutney_environment()

    list_instances = []

    # collect all instance addresses from file
    with open(instances_path) as f:
        for line in f:
            instance = line.rstrip()
            list_instances.append(instance)

    print(list_instances)
    config_file_path = create_test_config_file_v3(tmppath=tmpdir, instance_address=list_instances,
                                                  num_instances=num_instances)
    assert config_file_path

    # Start an Onionbalance server and monitor for correct output with pexpect
    server = pexpect.spawn('./home/laura/onionbalance/onionbalance',
                            args=[
                                '--hs-version', 'v3',
                                '-i', chutney_config.get('client_ip'),
                                '-p', str(chutney_config.get('control_port')),
                                '-c', config_file_path,
                                '-v', 'debug',
                                '--is-testnet'
                            ], logfile=sys.stdout.buffer, timeout=5)
    time.sleep(1)

    # Check for expected output from Onionbalance
    server.expect(u"Loaded the config file")
    server.expect(list_instances)

    # Update config file and send SIGHUP
    list_updated_instances = []
    i = 0
    while i < num_instances:
        list_updated_instances.append(random_onionv3_address())
        i += 1

    config_file_path = update_test_config_file_v3(tmppath=tmpdir, instance_address=list_updated_instances,
                                                  num_instances=num_instances)
    assert config_file_path
    server.kill(signal.SIGHUP)
    server.expect(u"Signal SIGHUP received, reloading configuration")
    server.expect(u"Loaded the config file")
    server.expect(list_updated_instances)
