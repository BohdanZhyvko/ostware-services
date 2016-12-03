from scapy.all import *
from time import sleep
from threading import Thread
import unittest

PacketMatch = False


def packet_capture():
    pkts = sniff(timeout=5, filter="icmp")
    for packet in pkts:
        if packet.haslayer(Raw):
            if packet[Raw].load == 'Hello world':
                global PacketMatch
                PacketMatch = True


# end capture


# main
class TestSniffer(unittest.TestCase):
    def test_packets(self):
        t = Thread(target=packet_capture, args=())
        t.start()

        # sleep 1 second before sending packet
        sleep(1)
        # send packet
        send(IP(dst='127.0.0.1') / ICMP() / "Hello world")

        t.join()
        self.assertTrue(PacketMatch, 'packet was not captured')


if __name__ == '__main__':
    unittest.main()
