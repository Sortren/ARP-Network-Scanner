import scapy.all as sc


def scan_for_devices(subnet_addr: str, MAC: str = None):
    """Scanning network for specific devices

    Args:
        subnet_addr ([str]): IP address of your subnet, 
                            input with mask: ex. '192.168.0.0/24'
        MAC ([str]): Two first octets of the devices' MAC Addres
                        you are looking for. Input ex.: 'sb:21'

    Returns:
        List[Dict]: Returns list of dicts with devices' IP and MAC addresses
                    based on MAC defined in args
    """

    # pdst -> Target hardware address (THA)
    packet = sc.Ether(dst="ff:ff:ff:ff:ff:ff") / sc.ARP(pdst=subnet_addr)

    """
    ans: Dict[str] -> answered packets
    unans: Dict[str] -> unanswered packets
    timeout -> when host doesn't answer we wait 2 seconds
    retry -> packet will be sent one more time after timeout
    verbose -> deletes unnecessary text in return of ans
    """

    ans, unans = sc.srp(packet, timeout=2, retry=1, verbose=False)

    filtered_devices = []

    for sent, received in ans:
        if MAC.lower() in received.hwsrc[:5]:
            filtered_devices.append(
                {
                    # psrc -> Sender protocol address (SPA)
                    'IP': received.psrc,
                    # hwsrc -> Sender hardware address (SHA)
                    'MAC': received.hwsrc
                }
            )

    return filtered_devices