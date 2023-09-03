from types import SimpleNamespace

from onionbalance.config_generator.config_generator import ConfigGenerator


def test_config_generation(self=None):
    args = SimpleNamespace(config='/home/laura/Documents/onionbalance/config.yaml', hs_version='v3', ip='127.0.0.1', is_testnet=False, port=6666, socket='/var/run/tor/control', verbosity='info')
    config_generator = ConfigGenerator(args, interactive = False)
    config_generator.gather_information()

