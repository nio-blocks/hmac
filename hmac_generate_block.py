from enum import Enum
import hashlib
import hmac
from nio import Block
from nio.block.mixins import EnrichSignals
from nio.properties import BoolProperty, SelectProperty, StringProperty, \
    Property, VersionProperty


class Algorithms(Enum):

    MD5 = 'md5'
    SHA1 = 'sha1'
    SHA256 = 'sha256'
    SHA384 = 'sha384'
    SHA512 = 'sha512'

class HMACgenerate(EnrichSignals, Block):

    key = Property(title='Key', default='[[HMAC_KEY]]')
    message = Property(title='Message')
    algorithm = SelectProperty(
        Algorithms,
        title='Hashing Algorithm',
        default=Algorithms.SHA256,
        advanced=True)
    binary = BoolProperty(
        title='Binary Output',
        default=False,
        advanced=True)
    output = StringProperty(
        title='Output Attribute',
        default='hash',
        advanced=True)
    version = VersionProperty('0.2.0')

    def process_signal(self, signal, input_id=None):
        key = self.key(signal)
        message = self.message(signal)
        if not self._check_types(key, message):
            return  # error has been logged
        key, message = self._encode_strings(key, message)
        algorithm = getattr(hashlib, self.algorithm(signal).value)
        message_hash = hmac.new(key, message, algorithm)
        if not self.binary(signal):
            output = message_hash.hexdigest()
        else:
            output = message_hash.digest()
        out_attr = self.output(signal)
        signal_dict = {out_attr: output}
        return self.get_output_signal(signal_dict, signal)

    def _check_types(self, key, message):
        valid_types = (bytes, bytearray, str)
        if not isinstance(key, valid_types):
            key_type = type(key).__name__
            err_msg = 'Invalid key type: {}'
            self.logger.error(err_msg.format(key_type))
            return False
        if not isinstance(message, valid_types):
            message_type = type(message).__name__
            err_msg = 'Invalid message type: {}'
            self.logger.error(err_msg.format(message_type))
            return False
        return True
        
    def _encode_strings(self, key, message):
        if isinstance(key, str):
            try:
                key = key.encode('utf-8')
            except:
                err_msg = 'Failed to encode key using UTF-8'
                self.logger.error(err_msg)  # do not log the key
        if isinstance(message, str):
            try:
                message = message.encode('utf-8')
            except:
                err_msg = 'Failed to encode message using UTF-8: \"{}\"'
                self.logger.error(err_msg.format(message))
        return key, message
