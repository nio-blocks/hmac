import hashlib
from unittest.mock import patch, Mock
from nio.block.terminals import DEFAULT_TERMINAL
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
                'key': 'foo',
                'message': 'an important message',
                'output': 'bar',
            }),
        ])
        blk.stop()
        mock_hmac.assert_called_once_with(
            b'foo', b'an important message', hashlib.md5)
        self.assert_num_signals_notified(1)
        self.assertDictEqual(
            self.last_notified[DEFAULT_TERMINAL][0].to_dict(),
            {
                'bar': 'hash-value'
            })

    @patch('hmac.new')
    def test_signal_enrichment(self, mock_hmac):
        """Signal Enrichment is implemented."""
        mock_hash_obj = Mock()
        mock_hash_obj.hexdigest.return_value = 'hash-value'
        mock_hmac.return_value = mock_hash_obj
        blk = HMACgenerate()
        config = {
            'enrich': {'exclude_existing': False},
            'message': 'an important message',
        }
        self.configure_block(blk, config)
        blk.start()
        blk.process_signals([
            Signal({
                'et': 'cetera',
            }),
        ])
        blk.stop()
        self.assert_num_signals_notified(1)
        self.assertDictEqual(
            self.last_notified[DEFAULT_TERMINAL][0].to_dict(),
            {
                'et': 'cetera',
                'hash': 'hash-value',
            })

    @patch('hmac.new')
    def test_algorithm_selection(self, mock_hmac):
        """Hash algorithm can be selected and evaluated."""
        blk = HMACgenerate()
        config = {
            'algorithm': '{{ $algorithm }}',
            'message': 'an important message',
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
        ])
        blk.stop()
        self.assertEqual(
            mock_hmac.call_args_list[0][0],
            (b'[[HMAC_KEY]]', b'an important message', hashlib.md5))
        self.assertEqual(
            mock_hmac.call_args_list[1][0],
            (b'[[HMAC_KEY]]', b'an important message', hashlib.sha1))
        self.assertEqual(
            mock_hmac.call_args_list[2][0],
            (b'[[HMAC_KEY]]', b'an important message', hashlib.sha256))
