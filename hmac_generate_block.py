from enum import Enum
import hashlib
import hmac
from nio import Block
from nio.block.mixins import EnrichSignals
from nio.properties import SelectProperty, StringProperty, VersionProperty


class Algorithms(Enum):

    MD5 = 'md5'
    SHA1 = 'sha1'
    SHA256 = 'sha256'

class HMACgenerate(EnrichSignals, Block):

    key = StringProperty(title='Key', default='[[HMAC_KEY]]')
    message = StringProperty(title='Message')
    algorithm = SelectProperty(
        Algorithms,
        title='Hashing Algorithm',
        default=Algorithms.SHA1,
        advanced=True)
    output = StringProperty(
        title='Output Attribute',
        default='hash',
        advanced=True)
    version = VersionProperty('0.1.0')

    def process_signal(self, signal, input_id=None):
        message_bytes = bytes(self.message(signal), 'utf-8')
        key_bytes = bytes(self.key(signal), 'utf-8')
        algorithm = getattr(hashlib, self.algorithm(signal).value)
        message_hash = hmac.new(key_bytes, message_bytes, algorithm).hexdigest()
        out_attr = self.output(signal)
        signal_dict = {out_attr: message_hash}
        return self.get_output_signal(signal_dict, signal)
