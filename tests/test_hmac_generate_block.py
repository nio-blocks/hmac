import hashlib
from unittest.mock import patch, Mock
from nio.signal.base import Signal
from nio.testing.block_test_case import NIOBlockTestCase
from ..hmac_generate_block import HMACgenerate


class TestGenerate(NIOBlockTestCase):

    @patch('hmac.new')
    def test_hashing(self, mock_hmac):
        """Incoming signal evaluations are hashed."""
        mock_hash_obj = Mock()
        mock_hash_obj.hexdigest.return_value = 'hash-value'
        mock_hmac.return_value = mock_hash_obj
        blk = HMACgenerate()
        config = {
            'key': '{{ $key }}',
            'message': '{{ $message }}',
            'output': '{{ $output }}',
        }
        self.configure_block(blk, config)
        blk.start()
        blk.process_signals([
            Signal({
                'key': b'foo',
                'message': b'an important message',
                'output': 'bar',
            }),
        ])
        blk.stop()
        mock_hmac.assert_called_once_with(
            b'foo', b'an important message', hashlib.sha256)
        mock_hash_obj.hexdigest.assert_called_once_with()
        mock_hash_obj.digest.assert_not_called()
        self.assert_num_signals_notified(1)
        self.assert_last_signal_notified(Signal(
            {
                'bar': 'hash-value'
            }
        ))

    @patch('hmac.new')
    def test_signal_enrichment(self, mock_hmac):
        """Signal Enrichment is implemented."""
        mock_hash_obj = Mock()
        mock_hash_obj.hexdigest.return_value = 'hash-value'
        mock_hmac.return_value = mock_hash_obj
        blk = HMACgenerate()
        config = {
            'enrich': {'exclude_existing': False},
            'message': '{{ $message }}',
        }
        self.configure_block(blk, config)
        blk.start()
        blk.process_signals([
            Signal({
                'message': b'an important message',
            }),
        ])
        blk.stop()
        self.assert_num_signals_notified(1)
        self.assert_last_signal_notified(Signal(
            {
                'message': b'an important message',
                'hash': 'hash-value',
            }
        ))

    @patch('hmac.new')
    def test_algorithm_selection(self, mock_hmac):
        """Hash algorithm can be selected and evaluated."""
        blk = HMACgenerate()
        config = {
            'algorithm': '{{ $algorithm }}',
            'key': b'foobarbaz',
            'message': b'an important message',
        }
        self.configure_block(blk, config)
        blk.start()
        blk.process_signals([
            Signal({
                'algorithm': 'md5',
            }),
            Signal({
                'algorithm': 'sha1',
            }),
            Signal({
                'algorithm': 'sha256',
            }),
            Signal({
                'algorithm': 'sha384',
            }),
            Signal({
                'algorithm': 'sha512',
            }),
        ])
        blk.stop()
        self.assertEqual(
            mock_hmac.call_args_list[0][0],
            (b'foobarbaz', b'an important message', hashlib.md5))
        self.assertEqual(
            mock_hmac.call_args_list[1][0],
            (b'foobarbaz', b'an important message', hashlib.sha1))
        self.assertEqual(
            mock_hmac.call_args_list[2][0],
            (b'foobarbaz', b'an important message', hashlib.sha256))
        self.assertEqual(
            mock_hmac.call_args_list[3][0],
            (b'foobarbaz', b'an important message', hashlib.sha384))
        self.assertEqual(
            mock_hmac.call_args_list[4][0],
            (b'foobarbaz', b'an important message', hashlib.sha512))

    @patch('hmac.new')
    def test_string_encoding(self, mock_hmac):
        """Key and Message are encoded to bytes if given a string."""
        blk = HMACgenerate()
        config = {
            'key': 'foobarbaz',
            'message': 'an important message',
        }
        self.configure_block(blk, config)
        blk.start()
        blk.process_signals([Signal()])
        blk.stop()
        self.assertEqual(
            mock_hmac.call_args_list[0][0],
            (b'foobarbaz', b'an important message', hashlib.sha256))

    @patch('hmac.new')
    def test_invalid_types(self, mock_hmac):
        """Message to be hashed is not a valid type, and is handled."""
        blk = HMACgenerate()
        config = {
            'message': 3.14159,
        }
        self.configure_block(blk, config)
        blk.start()
        blk.process_signals([Signal()])
        blk.stop()
        mock_hmac.assert_not_called()

    @patch('hmac.new')
    def test_binary_output(self, mock_hmac):
        """Optional binary output instead of hexdigest."""
        mock_hash_obj = Mock()
        mock_hmac.return_value = mock_hash_obj
        blk = HMACgenerate()
        config = {
            'binary': '{{ $binary }}',
            'message': 'an important message',
        }
        self.configure_block(blk, config)
        blk.start()
        blk.process_signals([Signal({'binary': True})])
        blk.stop()
        mock_hash_obj.digest.assert_called_once_with()
        mock_hash_obj.hexdigest.assert_not_called()
