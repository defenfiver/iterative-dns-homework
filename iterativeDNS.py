from dnslib import DNSRecord, DNSHeader, DNSBuffer, DNSQuestion, RR, QTYPE, RCODE
from socket import socket, SOCK_DGRAM, AF_INET
import validators

"""
There are 13 root servers defined at https://www.iana.org/domains/root/servers
"""

ROOT_SERVER = "192.58.128.30"    # Verisign, Inc Root Server
DNS_PORT = 53
cache = []


def get_dns_record(udp_socket, domain: str, parent_server: str, record_type, final=False):
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
        # print("Query failed")
        return

    # Parse the question section #2
    for k in range(header.q):
        q = DNSQuestion.parse(buff)
        # print(f"Question-{k} {repr(q)}")

    # Parse the answer section #3
    for k in range(header.a):
        a = RR.parse(buff)
        # print(f"Answer-{k} {repr(a)}")
        if a.rtype == QTYPE.A and final:
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
        if str(additional.rname) == returnInfo[1] and len(returnInfo) < 3 and additional.rtype !=28:
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
    inCacheSep, newAdr = checkCache(_domain_name, True)
    if inCacheSep:
        print(f'IP Address for {domain_name}: {newAdr[3]}, resovled from cache\n')
        return
    adr = 0
    # cache formated as [id, server looked up, name server, IP address, rtype
    inCache, newAdr = checkCache(f'{splitName[-2]}.{splitName[-1]}', False)
    if inCache:
        adr = newAdr
        splitName[-2] = f'{splitName[-2]}.{splitName[-1]}'
        splitName.pop(-1)
        print(f'{adr[1]} Authoritative name server consulted: {adr[2]}, obtained from cache')
    else:
        inCache, newAdr = checkCache(splitName[-1], False)
        if inCache:
            adr = newAdr
            print(f'{adr[1]} TLD name server consulted: {adr[2]}, obtained from cache')

    while True:
        if not adr:
            if type(splitName) == list:
                adr = get_dns_record(_sock, splitName[-1], params[0], params[1])
            else:
                adr = get_dns_record(_sock, splitName, params[0], params[1], True)
                adr.insert(0, len(cache))
                cache.append(adr)
                print(f'IP Address for {_domain_name}: {adr[3]}, resovled from authoritative name server\n')
                return
            if adr == None:
                print(f'{_domain_name} is not a valid domain name\n')
                return
            if len(adr) == 4:
                adr.insert(0, len(cache))
                cache.append(adr)
        if len(splitName) == len(_domain_name.split(".")):
            params = [adr[3], adr[4]]
            splitName[-2] = f'{splitName[-2]}.{splitName[-1]}'
            splitName.pop(-1)
            if not inCache:
                print(f'{adr[1]} TLD name server consulted: {adr[2]}, obtained from root server')
        elif len(adr) == 2:
            print(f'Alias for {_domain_name} found: {adr[1]}')
            return nameResolution(adr[1], _sock)
        else:
            params = [adr[3], adr[4]]
            splitName = _domain_name
            finished = True
            if not inCache: 
                print(f'{adr[1]} Authoritative name server consulted: {adr[2]}, obtained from TLD name server')
        adr = 0
        inCache = False

            

def removeFromCache(toRemove):
    if toRemove >= len(cache):
        print(f'Id: {toRemove} was not found in cache\n')
        return 
    for i in range(len(cache)):
        if cache[i][0] == toRemove:
            cache.pop(i)
            print(f'Id: {i} removed from cache\n')
            break
    for i in range(len(cache)):  # Renumbers items in cache after item is removed
        cache[i][0] = i

def checkCache(domain_name, finished):
    # cache formated as [id, server looked up, name server, IP address, rtype]
    cacheIter = domain_name
    for entry in cache:
        if (cacheIter == entry[1] or f'{cacheIter}.' == entry[1]):
            if (finished and entry[2] is None) or (not finished and entry[2] is not None):
                return True, entry
    return False, None


if __name__ == '__main__':
    # Create a UDP socket
    sock = socket(AF_INET, SOCK_DGRAM)
    sock.settimeout(2)
    while True:
        domain_name = input("Enter a domain name or .commands > ")
        # Main Command Loop
        if domain_name == ".exit":
            print("Exiting...")
            break
        elif domain_name == ".commands":
            print(".exit: exits program")
            print(".list: Lists items in the cache")
            print(".clear: Clears the cache")
            print(".remove #: Removes the specified cache entry\n")
        elif domain_name == ".list":
            for i in cache:
                print(f'Id: {i[0]} Server: {i[1]} Name Server:{i[2]} IP Adress: {i[3]}')
            if not cache:
                print("Cache is empty")
            print()
        elif domain_name == ".clear":
            cache = []
            print("Cache Cleared\n")
        elif domain_name.startswith(".remove"):
            toRemove = domain_name.split()[-1]
            try:
                removeFromCache(int(toRemove))
                    
            except ValueError:
                print(f'{toRemove} is not a number\n')
        else:
            if domain_name.startswith("https://"):
                domain_name = domain_name[8:]
            if not validators.domain(domain_name):
                print(domain_name, " Is not a valid domain name or command\n")
            else:
                nameResolution(domain_name, sock)

    sock.close()
