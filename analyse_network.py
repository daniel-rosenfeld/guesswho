from scapy.all import *
from ipaddress import ip_address
from mac_vendor_lookup import MacLookup, VendorNotFoundError


class AnalyzeNetwork:
    def __init__(self, pcap_path):
        """
        pcap_path (string): path to a pcap file
        """
        self.pcap_path = pcap_path
        self.scapy_pcap = rdpcap(pcap_path)

    def _is_private_ip(self, ip: str):
        return ip_address(ip).is_private

    def _get_vendor(self, mac: str):
        try:
            return MacLookup().lookup(mac)
        except Exception:
            return "Unknown"

    def _initiate_info(self, mac: str = "Unknown", ip: str = "Unknown") -> dict:
        info = dict()
        info["MAC"] = mac
        info["IP"] = ip
        info["VENDOR"] = self._get_vendor(mac)
        info["DEFULT_TTL"] = "Unknown"
        info["ICMP_PACKET_LEN"] = "Unknown"
        info["ICMP_PACKET_ID"] = "Unknown"
        info["ICMP_PACKET_SEQ"] = "Unknown"
        info["USING_HTTP"] = "False"
        info["USING_HTTPS"] = "False"
        info["USING_DNS"] = "False"
        return info

    def _check_and_update_info(self, info: dict, packet: Packet) -> dict:
        if (
            packet.haslayer("ICMP")
            and packet["ICMP"].type == 8
            and info["ICMP_PACKET_LEN"] != "Unknwon"
        ):
            info["ICMP_PACKET_LEN"] = len(packet)
            info["ICMP_PACKET_ID"] = packet["ICMP"].id
            info["ICMP_PACKET_SEQ"] = packet["ICMP"].seq
        elif packet.haslayer("TCP"):
            if (
                packet["TCP"].dport == 80
                or packet.haslayer("Raw")
                and b"HTTP" in packet["Raw"].load
            ):
                info["USING_HTTP"] = "True"
            elif packet["TCP"].dport == 443:
                info["USING_HTTPS"] = "True"
        return info

    def _calculate_windows_vs_linux_score(self, info: dict) -> int:
        score = 0

        if info["ICMP_PACKET_LEN"] != "Unknown":
            if info["ICMP_PACKET_LEN"] == 98:
                score += 1
            elif info["ICMP_PACKET_LEN"] == 74:
                score -= 1

        if info["ICMP_PACKET_ID"] != "Unknown":
            if info["ICMP_PACKET_ID"] != 1:
                score += 1
            else:
                score -= 1

        if info["ICMP_PACKET_SEQ"] != "Unknown":
            if info["ICMP_PACKET_SEQ"] == 1:
                score += 1
            else:
                score -= 1

        if info["DEFULT_TTL"] != "Unknown":
            if 62 <= info["DEFULT_TTL"] <= 64:
                score += 1
            elif 126 <= info["DEFULT_TTL"] <= 128:
                score -= 1

        return score

    def get_ips(self) -> list[str]:
        """returns a list of ip addresses (strings) that appear in
        the pcap"""
        ips = set()
        for packet in self.scapy_pcap:
            if packet.haslayer("IP"):
                ips.add(packet["IP"].src)
                ips.add(packet["IP"].dst)
            if packet.haslayer("ARP"):
                ips.add(packet["ARP"].pdst)
                ips.add(packet["ARP"].psrc)

        return list(ips)

    def get_macs(self) -> list[str]:
        """returns a list of MAC addresses (strings) that appear in
        the pcap"""
        macs = set()
        for packet in self.scapy_pcap:
            if packet.haslayer("Ether"):
                macs.add(packet["Ether"].src)
                macs.add(packet["Ether"].dst)
            if packet.haslayer("ARP"):
                macs.add(packet["ARP"].hwdst)
                macs.add(packet["ARP"].hwsrc)

        return list(macs)

    def guess_os(self, info: dict) -> str:
        score = self._calculate_windows_vs_linux_score(info)
        if score > 0:
            return "Linux"
        elif score < 0:
            return "Windows"
        return "Unknown"

    def get_info_by_mac(self, mac: str) -> dict | None:
        if mac == "ff:ff:ff:ff:ff:ff":
            return None

        info = self._initiate_info(mac=mac)

        for packet in self.scapy_pcap:
            if (
                packet.haslayer("ARP")
                and packet["ARP"].op == 2
                and mac == packet["ARP"].hwsrc
            ):
                info["IP"] = packet["ARP"].psrc

            if packet.haslayer("Ether") and packet.haslayer("IP"):
                if packet["Ether"].src == mac and self._is_private_ip(packet["IP"].src):
                    info["IP"] = packet["IP"].src
                    info["DEFULT_TTL"] = packet["IP"].ttl
                    info = self._check_and_update_info(info, packet)

                if packet["Ether"].dst == mac and self._is_private_ip(packet["IP"].dst):
                    info["IP"] = packet["IP"].dst

        info["GUESSED_OS"] = self.guess_os(info)
        return info

    def get_info_by_ip(self, ip: str) -> dict:
        """returns a dict with all information about the device with
        given IP address"""

        info = self._initiate_info(ip=ip)

        if not self._is_private_ip(ip):
            return info

        for packet in self.scapy_pcap:
            if (
                packet.haslayer("ARP")
                and packet["ARP"].op == 2
                and ip == packet["ARP"].psrc
            ):
                info["MAC"] = packet["ARP"].hwsrc
                info["VENDOR"] = self._get_vendor(packet["ARP"].hwsrc)

            if packet.haslayer("Ether") and packet.haslayer("IP"):
                if packet["IP"].src == ip:
                    info["MAC"] = packet["Ether"].src
                    info["DEFULT_TTL"] = packet["IP"].ttl
                    info = self._check_and_update_info(info, packet)

                if packet["IP"].dst == ip:
                    info["MAC"] = packet["Ether"].dst

        info["VENDOR"] = self._get_vendor(info["MAC"])
        info["GUESSED_OS"] = self.guess_os(info)
        return info

    def get_info(self) -> list[dict]:
        info_by_mac = []
        info_by_ip = []

        for mac in self.get_macs():
            mac_info = self.get_info_by_mac(mac)
            if mac_info:
                info_by_mac.append(mac_info)

        for ip in self.get_ips():
            info_by_ip.append(self.get_info_by_ip(ip))

        info_list = info_by_mac
        seen_devices = set([frozenset(info) for info in info_list])

        for info in info_by_ip:
            frozen_info = frozenset(info)
            if frozen_info not in seen_devices:
                info_list.append(info)
                seen_devices.add(frozen_info)

        return info_list

    def __repr__(self):
        raise NotImplementedError

    def __str__(self):
        raise NotImplementedError


if __name__ == "__main__":
    my_analyzer = AnalyzeNetwork("pcap-03.pcapng")
    print(json.dumps(my_analyzer.get_info(), indent=4))
