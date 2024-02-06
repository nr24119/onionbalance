from test.functional.util import create_test_config_file_v3


def test_chutney(tmpdir, num_instances=25):
    """
    functional test to create a config file used for testing in a chutney net
    """

    # collect all instances (onion addresses) from current chutney net (/chutney/net/nodes.169...):
    # cat */hidden_service/hostname > <path_to_your_instances_file>
    # set path to file here
    instances_path = "<path_to_your_instances_file>"

    list_instances = []

    # collect all instance addresses from file
    with open(instances_path) as f:
        for line in f:
            instance = line.rstrip()
            list_instances.append(instance)

    print(list_instances)
    config_file_path = create_test_config_file_v3(tmppath=tmpdir, instance_address=list_instances,
                                                  num_instances=num_instances)
    print(config_file_path)
    assert config_file_path

    # Manually set config-path, install and start Onionbalance in terminal
    # sudo python3 setup.py install
    # ./onionbalance.py --hs-version v3 -i 127.0.0.1 -p 8008 -c <path_to_config.yaml> -v debug --is-testnet

