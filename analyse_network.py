class AnalyzeNetwork:
    def __init__(self, pcap_path):
        """
        pcap_path (string): path to a pcap file
        """
        self.pcap_path = pcap_path

    def get_ips(self):
        """returns a list of ip addresses (strings) that appear in
        the pcap"""
        raise NotImplementedError

    def get_macs(self):
        """returns a list of MAC addresses (strings) that appear in
        the pcap"""
        raise NotImplementedError

    def get_info_by_mac(self, mac):
        """returns a dict with all information about the device with
        given MAC address"""
        raise NotImplementedError

    def get_info_by_ip(self, ip):
        """returns a dict with all information about the device with
        given IP address"""
        raise NotImplementedError

    def get_info(self):
        """returns a list of dicts with information about every
        device in the pcap"""
        raise NotImplementedError

    def __repr__(self):
        raise NotImplementedError

    def __str__(self):
        raise NotImplementedError
