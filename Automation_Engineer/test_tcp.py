import unittest
from sniffer import sniffer


class TestSnifferTCP(unittest.TestCase):
    def test_sniff(self):
        self.assertTrue(100 <= sniffer('tcp'), 'less then 100')


if __name__ == '__main__':
    unittest.main()
