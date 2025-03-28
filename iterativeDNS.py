from dnslib import DNSRecord, DNSHeader, DNSBuffer, DNSQuestion, RR, QTYPE, RCODE
from socket import socket, SOCK_DGRAM, AF_INET
import validators

"""
There are 13 root servers defined at https://www.iana.org/domains/root/servers
"""

ROOT_SERVER = "192.58.128.30"    # Verisign, Inc Root Server
DNS_PORT = 53
cache = []


def get_dns_record(udp_socket, domain: str, parent_server: str, record_type):
    q = DNSRecord.question(domain, qtype=record_type)
    q.header.rd = 0   # Recursion Desired?  NO **DO NOT CHANGE**
    # print("DNS query", repr(q))
    udp_socket.sendto(q.pack(), (str(parent_server), DNS_PORT))
    pkt, _ = udp_socket.recvfrom(8192)
    buff = DNSBuffer(pkt)

    returnInfo = []
    """
    RFC1035 Section 4.1 Format
    
    The top level format of DNS message is divided into five sections:
    1. Header
    2. Question
    3. Answer
    4. Authority
    5. Additional
    """

    header = DNSHeader.parse(buff)
    # print("DNS header", repr(header))
    if q.header.id != header.id:
        print("Unmatched transaction")
        return
    if header.rcode != RCODE.NOERROR:
        print("Query failed")
        return

    # Parse the question section #2
    for k in range(header.q):
        q = DNSQuestion.parse(buff)
        # print(f"Question-{k} {repr(q)}")

    # Parse the answer section #3
    for k in range(header.a):
        a = RR.parse(buff)
        # print(f"Answer-{k} {repr(a)}")
        if a.rtype == QTYPE.A:
            return [domain, None, str(a.rdata), str(a.rtype)]

    # Parse the authority section #4
    for k in range(header.auth):
        auth = RR.parse(buff)
        # print(f"Authority-{k} {repr(auth)} Name: {auth.rname}")
        if k == 0:
            returnInfo.append(str(auth.rname))
            returnInfo.append(str(auth.rdata))
            break

    rtypeDict = {1:"A", 2:"NS", 5:"CNAME"}
    # Parse the additional section #5
    for k in range(header.ar):
        additional = RR.parse(buff)
        # print(f"Additional-{k} {repr(additional)} Name: {additional.rname}")
        if str(additional.rname) == returnInfo[1] and len(returnInfo) < 3:
            returnInfo.append(str(additional.rdata))
            returnInfo.append(rtypeDict[additional.rtype])
            break
            
    # return something with addition section
    # adr.rdata is the IP address
    # adr.rtype is the type of data A=IPv4, AAAA=IPv6, NS=Host Name, CNAME=Domain Name
    return returnInfo


def nameResolution(_domain_name, _sock):
    params = [ROOT_SERVER, "NS"]
    if _domain_name.endswith("."):
        _domain_name = _domain_name[:-1]
    splitName = _domain_name.split(".")
    finished = False
    while True:
        adr = 0
        # cache formated as [id, server looked up, name server, IP address, rtype]
        for entry in cache:
            if splitName[-1] == entry[0] or f'{splitName[-1]}.' == entry[0]:
                adr = entry
                print("\t" + splitName[-1] + "found in cache")
        if not adr:
            if type(splitName) == list:
                adr = get_dns_record(_sock, splitName[-1], params[0], params[1])
            else:
                adr = get_dns_record(_sock, splitName, params[0], params[1])
                adr.insert(0, len(cache))
                cache.append(adr)
                print(f'IP Adress: {adr[3]}')
                return

            adr.insert(0, len(cache))
            cache.append(adr)
        if len(splitName) == len(_domain_name.split(".")):
            params = [adr[3], adr[4]]
            splitName[-2] = f'{splitName[-2]}.{splitName[-1]}'
            splitName.pop(-1)
        elif len(adr) == 3:
            return nameResolution(adr[2], _sock)

        else:
            params = [adr[3], adr[4]]
            splitName = _domain_name


if __name__ == '__main__':
    # Create a UDP socket
    sock = socket(AF_INET, SOCK_DGRAM)
    sock.settimeout(2)
    # [[id, domain, IP], [id, domain, IP]...]
    while True:
        domain_name = input("Enter a domain name or .commands > ")
      
        if domain_name == ".exit":
            print("Exiting...")
            break
        elif domain_name == ".commands":
            print(".exit: exits program")
            print(".list: Lists items in the cache")
            print(".clear: Clears the cache")
            print(".remove #: Removes the specified cache entry")
        elif domain_name == ".list":
            print(cache)  # Implement for List of lists with 3 values
        elif domain_name == ".clear":
            cache = []
            print("Cache Cleared")
        elif domain_name.startswith(".remove"):
            try:
                num = domain_name.split(" ")
                for i in cache:  # Searches and removes specified cache entry
                    if i[0] == num:
                        cache.remove(i)
                for i in range(len(cache)):  # Renumbers items in cache after item is removed
                    cache[i][0] = i
            except:  # add exceptions
                pass
        else:
            if not validators.domain(domain_name):
                print(domain_name, " Is not a valid domain name or command")
            else:
                nameResolution(domain_name, sock)

    # Get all the .edu name servers from the ROOT SERVER
    # get_dns_record(sock, "edu", ROOT_SERVER, "NS")  # The picture in the repo
  
    # The following function calls are FAILED attempts to use Google Public DNS
    # (1) to get name servers which manages gvsu.edu
    # (2) to resolve the IP address of www.gvsu.edu
    # get_dns_record(sock, "gvsu.edu", "8.8.8.8", "NS")      # (1)
    # get_dns_record(sock, "www.gvsu.edu", "8.8.8.8", "A")   # (2)
  
    sock.close()
