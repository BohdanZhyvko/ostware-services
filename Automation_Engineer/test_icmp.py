import unittest
from sniffer import sniffer


class TestSnifferICMP(unittest.TestCase):
    def test_sniff(self):
        self.assertTrue(10 <= sniffer('icmp'), 'less then 10')


if __name__ == '__main__':
    unittest.main()
