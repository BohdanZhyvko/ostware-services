import unittest
from sniffer import sniffer


class TestSnifferUDP(unittest.TestCase):
    def test_sniff(self):
        self.assertTrue(50 <= sniffer('udp'), 'less then 50')


if __name__ == '__main__':
    unittest.main()
