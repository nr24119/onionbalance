import datetime
import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

import stem
import stem.descriptor.hidden_service
from stem.descriptor.hidden_service import HiddenServiceDescriptorV3

import onionbalance.common.descriptor
from onionbalance.common import log
import onionbalance.common.util

import onionbalance.hs_v3.instance
from onionbalance.hs_v3 import params
from onionbalance.hs_v3 import hashring
from onionbalance.hs_v3 import descriptor
from onionbalance.hs_v3 import tor_ed25519
from onionbalance.hs_v3.descriptor import BadDescriptor

logger = log.get_logger()


class OnionbalanceService(object):
    """
    Service represents a front-facing hidden service which should
    be load-balanced.
    """

    def __init__(self, service_config_data, config_path):
        """
        With 'config_data' straight out of the config file, create the service and its instances.
        'config_path' is the full path to the config file.

        Raise ValueError if the config file is not well formatted
        """
        # Is our private key in Tor's extended key format?
        self.is_priv_key_in_tor_format = False

        # Load private key and onion address from config
        # (the onion_address also includes the ".onion")
        self.identity_priv_key, self.onion_address = self._load_service_keys(service_config_data, config_path)

        # XXX This is an epic hack! If we are using keys in tor's extended
        # format, we basically override stem's function for signing with
        # blinded keys because it assumes that its keys are in standard
        # non-extended format. To avoid a double key extension we use our own
        # function...  This will prove to be a problem if we ever move to
        # multiple services per onionbalance, or if stem changes its code
        # behind our backs.
        if self.is_priv_key_in_tor_format:
            stem.descriptor.hidden_service._blinded_sign = tor_ed25519._blinded_sign_with_tor_key

        # Now load up the instances
        self.instances = self._load_instances(service_config_data)

        # First descriptor for this service (the one we uploaded last)
        self.first_descriptor = None
        # Second descriptor for this service (the one we uploaded last)
        self.second_descriptor = None

    def has_onion_address(self, onion_address):
        """
        Return True if this service has this onion address
        """
        # Strip the ".onion" part of the address if it exists since some
        # subsystems don't use it (e.g. Tor sometimes omits it from control
        # port responses)
        my_onion_address = self.onion_address.replace(".onion", "")
        their_onion_address = onion_address.replace(".onion", "")

        return my_onion_address == their_onion_address

    def _load_instances(self, service_config_data):
        instances = []

        for config_instance in service_config_data['instances']:
            new_instance = onionbalance.hs_v3.instance.InstanceV3(config_instance['address'])
            instances.append(new_instance)

        # Some basic validation
        for instance in instances:
            if self.has_onion_address(instance.onion_address):
                logger.error("Config file error. Did you configure your frontend (%s) as an instance?",
                             self.onion_address)
                raise BadServiceInit

        return instances

    def _load_service_keys(self, service_config_data, config_path):
        # First of all let's load up the private key
        key_fname = service_config_data['key']
        config_directory = os.path.dirname(config_path)
        if not os.path.isabs(key_fname):
            key_fname = os.path.join(config_directory, key_fname)

        try:
            with open(key_fname, 'rb') as handle:
                pem_key_bytes = handle.read()
        except EnvironmentError as e:
            logger.critical("Unable to read service private key file ('%s')", e)
            raise BadServiceInit

        # Get the service private key
        # First try with the OBv3 PEM format
        identity_priv_key = None
        try:
            identity_priv_key = serialization.load_pem_private_key(pem_key_bytes, password=None, backend=default_backend())
        except ValueError as e:
            logger.warning("Service private key not in OBv3 format ('%s'). Trying tor's format...", e)

        # If the key was not in OBv3 PEM format, try the Tor binary format
        if not identity_priv_key:
            try:
                identity_priv_key = tor_ed25519.load_tor_key_from_disk(pem_key_bytes)
                self.is_priv_key_in_tor_format = True
            except ValueError as e:
                logger.warning("Service private key not in Tor format either ('%s'). Aborting.", e)
                raise BadServiceInit

        # Get onion address
        identity_pub_key = identity_priv_key.public_key()
        identity_pub_key_bytes = identity_pub_key.public_bytes(encoding=serialization.Encoding.Raw,
                                                               format=serialization.PublicFormat.Raw)
        onion_address = HiddenServiceDescriptorV3.address_from_identity_key(identity_pub_key_bytes)

        logger.warning("Loaded onion %s from %s", onion_address, key_fname)

        return identity_priv_key, onion_address

    def _intro_set_modified(self, is_first_desc):
        """
        Check if the introduction point set has changed since last publish.
        """
        if is_first_desc:
            last_upload_ts = self.first_descriptor.last_upload_ts
        else:
            last_upload_ts = self.second_descriptor.last_upload_ts

        if not last_upload_ts:
            logger.info("\t Descriptor never published before. Do it now!")
            return True

        for instance in self.instances:
            if not instance.intro_set_modified_timestamp:
                logger.info("\t Still dont have a descriptor for this instance")
                continue

            if instance.intro_set_modified_timestamp > last_upload_ts:
                logger.info("\t Intro set modified")
                return True

        logger.info("\t Intro set not modified")
        return False

    def _get_descriptor_lifetime(self):
        from onionbalance.hs_v3.onionbalance import my_onionbalance
        if my_onionbalance.is_testnet:
            return params.FRONTEND_DESCRIPTOR_LIFETIME_TESTNET
        else:
            return params.FRONTEND_DESCRIPTOR_LIFETIME

    def _descriptor_has_expired(self, is_first_desc):
        """
        Check if the descriptor has expired (hasn't been uploaded recently).

        If 'is_first_desc' is set then check the first descriptor of the
        service, otherwise the second.
        """
        if is_first_desc:
            last_upload_ts = self.first_descriptor.last_upload_ts
        else:
            last_upload_ts = self.second_descriptor.last_upload_ts

        descriptor_age = (datetime.datetime.utcnow() - last_upload_ts)
        descriptor_age = int(descriptor_age.total_seconds())
        if (descriptor_age > self._get_descriptor_lifetime()):
            logger.info("\t Our %s descriptor has expired (%s seconds old). Uploading new one.",
                        "first" if is_first_desc else "second", descriptor_age)
            return True
        else:
            logger.info("\t Our %s descriptor is still fresh (%s seconds old).",
                        "first" if is_first_desc else "second", descriptor_age)
            return False

    def _hsdir_set_changed(self, is_first_desc):
        """
        Return True if the HSDir has changed between the last upload of this
        descriptor and the current state of things
        """
        from onionbalance.hs_v3.onionbalance import my_onionbalance

        # Derive blinding parameter
        _, time_period_number = hashring.get_srv_and_time_period(is_first_desc)
        blinded_param = my_onionbalance.consensus.get_blinding_param(self._get_identity_pubkey_bytes(),
                                                                     time_period_number)

        # Get blinded key
        # TODO: hoho! this is dirty we are poking into internal stem API. We
        #       should ask atagar to make it public for us! :)
        blinded_key = stem.descriptor.hidden_service._blinded_pubkey(self._get_identity_pubkey_bytes(), blinded_param)

        # Calculate current responsible HSDirs
        try:
            responsible_hsdirs = hashring.get_responsible_hsdirs(blinded_key, is_first_desc)
        except hashring.EmptyHashRing:
            return False

        if is_first_desc:
            previous_responsible_hsdirs = self.first_descriptor.responsible_hsdirs
        else:
            previous_responsible_hsdirs = self.second_descriptor.responsible_hsdirs

        if set(responsible_hsdirs) != set(previous_responsible_hsdirs):
            logger.info("\t HSDir set changed (%s vs %s)",
                        set(responsible_hsdirs), set(previous_responsible_hsdirs))
            return True
        else:
            logger.info("\t HSDir set remained the same")
            return False

    def _should_publish_descriptor_now(self, is_first_desc, force_publish=False):
        """
        Return True if we should publish a descriptor right now
        """
        # If descriptor not yet uploaded, do it now!
        if is_first_desc and not self.first_descriptor:
            return True
        if not is_first_desc and not self.second_descriptor:
            return True

        # OK this is not the first time we publish a descriptor. Check various
        # parameters to see if we should try to publish again:
        return any([self._intro_set_modified(is_first_desc),
                    self._descriptor_has_expired(is_first_desc),
                    self._hsdir_set_changed(is_first_desc),
                    force_publish])

    def get_all_intros_for_publish(self):
        """
        Return an IntroductionPointSetV3 with all the intros of all the instances
        of this service.
        """
        all_intros = []

        for instance in self.instances:
            try:
                instance_intros = instance.get_intros_for_publish()
            except onionbalance.hs_v3.instance.InstanceHasNoDescriptor:
                logger.info("Entirely missing a descriptor for instance %s. Continuing anyway if possible",
                            instance.onion_address)
                continue
            except onionbalance.hs_v3.instance.InstanceIsOffline:
                logger.info("Instance %s is offline. Ignoring its intro points...",
                            instance.onion_address)
                continue

            all_intros.append(instance_intros)

        return descriptor.IntroductionPointSetV3(all_intros)

    def publish_descriptors(self):
        self._publish_descriptor(is_first_desc=True)
        self._publish_descriptor(is_first_desc=False)

    def _get_intros_for_desc(self):
        """
        Get the intros that should be included in a descriptor for this service.
        """
        all_intros = self.get_all_intros_for_publish()

        # Get number of instances that contributed to final intro point list
        n_instances = len(all_intros.intro_points)
        n_intros_wanted = n_instances * params.N_INTROS_PER_INSTANCE

        final_intros = all_intros.choose(n_intros_wanted)

        if (len(final_intros) == 0):
            logger.info("Got no usable intro points from our instances. Delaying descriptor push...")
            raise NotEnoughIntros

        logger.info("We got %d intros from %d instances. We want %d intros ourselves (got: %d)",
                    len(all_intros.get_intro_points_flat()), n_instances,
                    n_intros_wanted, len(final_intros))

        return final_intros

    def _publish_descriptor(self, is_first_desc):
        """
        Attempt to publish descriptor if needed.

        If 'is_first_desc' is set then attempt to upload the first descriptor
        of the service, otherwise the second.
        """
        from onionbalance.hs_v3.onionbalance import my_onionbalance

        if not self._should_publish_descriptor_now(is_first_desc):
            logger.info("No reason to publish %s descriptor for %s",
                        "first" if is_first_desc else "second",
                        self.onion_address)
            return

        try:
            intro_points = self._get_intros_for_desc()
        except NotEnoughIntros:
            return

        # Derive blinding parameter
        _, time_period_number = hashring.get_srv_and_time_period(is_first_desc)
        blinding_param = my_onionbalance.consensus.get_blinding_param(self._get_identity_pubkey_bytes(),
                                                                      time_period_number)
        # calculate descriptor size without intro points
        empty_intro_points = []
        try:
            empty_desc = descriptor.OBDescriptor(self.onion_address, self.identity_priv_key,
                                           blinding_param, empty_intro_points, is_first_desc)
        except descriptor.BadDescriptor:
            return

        available_space = self._calculate_space(empty_desc)

        num_descriptors = self._calculate_needed_desc(intro_points, available_space)

        # set Distinct Descriptor Mode if more than one descriptor is needed to fit backend instances resp. intro points
        if num_descriptors > 1:
            ddm = True
        else:
            ddm = False

        descriptors = self._create_descriptors(intro_points, num_descriptors, ddm, blinding_param, is_first_desc)


        # ddm_failsafe means that we can afford to store a single descriptor on multiple HSDirs
        # this is the case if the number of (sub)descriptors <= (HSDIR_N_REPLICAS * HSDIR_SPREAD_STORE) / 2
        # Example: num_descriptors = 3, HSDIR_SPREAD_STORE = 3, HSDIR_N_REPLICAS = 2 -> we have 3*2 HSDirs (=N_HSDIRS) available
        # our 3 descriptors can be distributed to 6 HSDirs, so every descriptor can be stored on 2 HSDirs
        # now we need only to figure out the addresses of the 2 HSDirs the descriptor will be uploaded to
        # it would probably be best to get the list of all usable addresses and then distribute to resp. descriptor
        # disadvantage: if e. g. num_descriptors = 4 and N_HSDIRS = 6 we only upload 4 descriptors and leave 2 HSDirs
        # without descriptor

        ddm_failsafe = self._load_failsafe_param(num_descriptors)

        # since all our descriptor have the same public key and are uploaded at the same time the responsible hsdirs
        # are the same for all of them
        try:
            responsible_hsdirs = self._get_responsible_hsdirs(descriptors[0], is_first_desc)
        except descriptor.BadDescriptor:
            return

        try:
            self._assign_responsible_hdsirs(responsible_hsdirs, descriptors)
        except BadServiceInit:
            return


        # Upload (sub)descriptor
        for desc in descriptors:
            i = 0
            self._upload_descriptor(my_onionbalance.controller.controller, desc, is_first_desc, desc.responsible_hsdirs, ddm, i)

            # It would be better to set last_upload_ts when an upload succeeds and
            # not when an upload is just attempted. Unfortunately the HS_DESC #
            # UPLOADED event does not provide information about the service and
            # so it can't be used to determine when descriptor upload succeeds
            desc.set_last_upload_ts(datetime.datetime.utcnow())
            desc.set_responsible_hsdirs(responsible_hsdirs)

            # Set the descriptor
            if is_first_desc:
                self.first_descriptor = desc
            else:
                self.second_descriptor = desc

    def _get_responsible_hsdirs(self, desc, is_first_desc):
        """
        return list of responsible HSDirs to upload our (sub)descriptor(s) to
        """
        blinded_key = desc.get_blinded_key()
        try:
            responsible_hsdirs = hashring.get_responsible_hsdirs(blinded_key, is_first_desc)
        except hashring.EmptyHashRing:
            logger.warning("Can't publish desc with no hash ring. Delaying...")
            return

        return responsible_hsdirs

    def _calculate_space(self, empty_desc):
        """
        calculate available space per (sub)descriptor to fit intro points
        """
        current_size = len(str(empty_desc))
        logger.info(
            "Size of descriptor without intro points is %s bytes", current_size)

        available_space = params.MAX_DESCRIPTOR_SIZE - current_size
        logger.info(
            "We have %s bytes per descriptor to fit our intro points", available_space)
        return available_space

    def _calculate_needed_desc(self, intro_points, available_space):
        """
        calculate number of (sub)descriptors needed to fit all intro points
        """
        needed_space = len(str(intro_points))

        logger.info("We need %s bytes of space to fit all intro points (have %s)", needed_space, available_space)

        num_descriptors = 0
        space = 0
        while needed_space > space:
            num_descriptors += 1
            space = num_descriptors * available_space
            print(space)

        logger.info("We need %d descriptor(s) to fit all intro points", num_descriptors)

        return num_descriptors

    def _create_descriptors(self, intro_points, num_descriptors, ddm, blinding_param, is_first_desc):
        """
        create (sub)descriptor(s) with assigned intro points
        """
        available_intro_points = intro_points.copy()
        descriptors = []
        # index needed for assigning intro points to descriptor
        index = len(available_intro_points) // num_descriptors
        i = 0
        while i < num_descriptors:
            # now assign intro points and create (sub)descriptor
            assigned_intro_points = []
            j = 0
            while j <= index:
                if len(available_intro_points) > 0:
                    assigned_intro_points.append(available_intro_points[0])
                    available_intro_points.pop(0)
                    logger.info("Assigned intro point %d to (sub)descriptor %d.", j + 1, i + 1)
                else:
                    logger.info("Assigned all intro points to our descriptor(s).")
                j += 1
            try:
                desc = descriptor.OBDescriptor(self.onion_address, self.identity_priv_key, blinding_param,
                                               assigned_intro_points, is_first_desc)
            except descriptor.BadDescriptor:
                return
            descriptors.append(desc)
            if ddm:
                logger.info(
                    "Service %s created %s descriptor of subdescriptor %d (%s intro points) (blinding param: %s) "
                    "(size: %s bytes). About to publish:",
                    self.onion_address, "first" if is_first_desc else "second", i + 1,
                    len(desc.intro_set), blinding_param.hex(), len(str(desc.v3_desc)))
            else:
                logger.info(
                    "Service %s created %s descriptor (%s intro points) (blinding param: %s) "
                    "(size: %s bytes). About to publish:",
                    self.onion_address, "first" if is_first_desc else "second",
                    len(desc.intro_set), blinding_param.hex(), len(str(desc.v3_desc)))
            i += 1

        return descriptors

    def _upload_descriptor(self, controller, ob_desc, is_first_desc, hsdirs, ddm, index):
        """
        Convenience method to upload a (sub)descriptor
        Handle some error checking and logging inside the Service class
        """

        ob_desc.set_last_publish_attempt_ts(datetime.datetime.utcnow())
        if ddm:
            logger.info("Uploading %s descriptor of subdescriptor %d for %s to %s",
                        "first" if is_first_desc else "second", index + 1,
                        self.onion_address, hsdirs)
        else:
            logger.info("Uploading %s descriptor for %s to %s",
                        "first" if is_first_desc else "second",
                        self.onion_address, hsdirs)

        if hsdirs and not isinstance(hsdirs, list):
            hsdirs = [hsdirs]

        while True:
            try:
                onionbalance.common.descriptor.upload_descriptor(controller,
                                                                 ob_desc.v3_desc,
                                                                 hsdirs=hsdirs,
                                                                 v3_onion_address=ob_desc.onion_address)
                break
            except stem.SocketClosed:
                logger.error("Error uploading descriptor %d for service "
                             "%s.onion. Control port socket is closed.",
                             index + 1, self.onion_address)
                onionbalance.common.util.reauthenticate(controller, logger)

            except stem.ControllerError:
                logger.exception("Error uploading descriptor %d for service "
                                 "%s.onion.", index + 1, self.onion_address)
                break

    def _get_identity_pubkey_bytes(self):
        identity_pub_key = self.identity_priv_key.public_key()
        return identity_pub_key.public_bytes(encoding=serialization.Encoding.Raw,
                                             format=serialization.PublicFormat.Raw)

    def _load_failsafe_param(self, num_descriptors):
        """
        determine if we can afford to upload (sub)descriptor(s) multiple times
        depending on the number of needed descriptors and the number of available HSDirs
        """
        if params.N_HSDIRS < num_descriptors:
            logger.error("We have not enough HSDirs configured to fit our %s (sub)descriptor(s).", num_descriptors)
            raise BadServiceInit
        elif params.N_HSDIRS // params.HSDIR_N_REPLICAS >= num_descriptors:
            logger.info("We have enough HSDirs configured to fit our %d (sub)descriptor(s) multiple times "
                        "(Failsafe = True).",
                        num_descriptors)
            return True
        elif params.N_HSDIRS // params.HSDIR_N_REPLICAS < num_descriptors:
            logger.info("We have enough HSDirs configured to fit our %d (sub)subdescriptor(s) once (Failsafe = False).",
                        num_descriptors)
            return False
        else:
            logger.error("Something went wrong. Maybe no N_HSDIRS set? Aborting.")
            raise BadServiceInit

    def _assign_responsible_hdsirs(self, responsible_hsdirs, descriptors):
        available_hsdirs = responsible_hsdirs.copy()
        index = len(available_hsdirs) // len(descriptors)
        i = 0
        while i < len(descriptors):
            # now assign hsdirs to our descriptor(s)
            assigned_hsdirs = []
            j = 0
            while j <= index:
                if len(available_hsdirs) > 0:
                    assigned_hsdirs.append(available_hsdirs[0])
                    logger.info("Assigned hsdir %s to (sub)descriptor %d.",
                                available_hsdirs[j].hsdir_node.get_hex_fingerprint(), i + 1)
                    available_hsdirs.pop(0)
                else:
                    logger.info("Assigned all hsdirs to our descriptor(s).")
                j += 1
            try:
                descriptors[i].set_responsible_hsdirs(assigned_hsdirs)
                logger.info("Assigned %d hsdirs to (sub)descriptor %d.",
                            len(descriptors[i].responsible_hsdirs), i + 1)
            except BadServiceInit:
                return

            i += 1

        # go through every hsdir in list and assign to descriptor
        #i = 0
        #while len(responsible_hsdirs) > 0:
            #descriptors[i].set_responsible_hsdirs(responsible_hsdirs[i])
            #responsible_hsdirs.pop(0)
            #i += 1


class NotEnoughIntros(Exception):
    pass


class BadServiceInit(Exception):
    pass
