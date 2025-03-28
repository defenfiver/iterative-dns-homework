from dnslib import DNSRecord, DNSHeader, DNSBuffer, DNSQuestion, RR, QTYPE, RCODE
from socket import socket, SOCK_DGRAM, AF_INET
import validators

"""
Cullen Simkins
3/28/25

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
    if q.header.id != header.id:
        print("Unmatched transaction")
        return
    if header.rcode != RCODE.NOERROR:
        return

    # Parse the question section #2, cannot be removed
    for k in range(header.q):
        q = DNSQuestion.parse(buff)

    # Parse the answer section #3
    for k in range(header.a):
        a = RR.parse(buff)
        if a.rtype == QTYPE.A and final:  # If it is an IPv4 Address and is looking for domain name IP Address
            return [domain, None, str(a.rdata), str(a.rtype)]

    # Parse the authority section #4
    for k in range(header.auth):
        auth = RR.parse(buff)
        if k == 0:  # Adds the first server and name server
            returnInfo.append(str(auth.rname))
            returnInfo.append(str(auth.rdata))
            break

    rtypeDict = {1:"A", 2:"NS"}
    # Parse the additional section #5
    for k in range(header.ar):
        additional = RR.parse(buff)
        # Searches through the addition sections until the IPv4 address and rtype corresponding to the first name server is found
        if str(additional.rname) == returnInfo[1] and len(returnInfo) < 3 and additional.rtype !=28:
            returnInfo.append(str(additional.rdata))
            returnInfo.append(rtypeDict[additional.rtype])
            break
    return returnInfo



def nameResolution(_domain_name, _sock):
    """
    _domain_name: The domain name being searched for
    _sock: The socket being used
    returns: None
    """
    params = [ROOT_SERVER, "NS"]
    if _domain_name.endswith("."):  # If an alias, there will be a "." at the end of the domain_name, which can cause problems
        _domain_name = _domain_name[:-1]
    splitName = _domain_name.split(".")
    adr = 0  # The entry either from the cache or to be added to the cache
    
    inCacheSep, newAdr = checkCache(_domain_name, True)  # Checks the Cache for the resolved IP Address
    if inCacheSep:
        print(f'IP Address for {domain_name}: {newAdr[3]}, resovled from cache\n')
        return
    inCache, newAdr = checkCache(f'{splitName[-2]}.{splitName[-1]}', False) # Checks the Cache for the Authoritative name server
    if inCache:  
        adr = newAdr
        # Combines to form the name server to be searched for by the TLD name server
        # This puts the following while loop into the correct state
        splitName[-2] = f'{splitName[-2]}.{splitName[-1]}'  
        splitName.pop(-1) 
        print(f'{adr[1]} Authoritative name server consulted: {adr[2]}, obtained from cache')
    inCache, newAdr = checkCache(splitName[-1], False)  # Checks the Cache for the TLD name server
    if inCache:
        adr = newAdr
        # No changes are made to splitName as the while loop will already be in the correct state just from finding the adr in cache
        print(f'{adr[1]} TLD name server consulted: {adr[2]}, obtained from cache')

    # cache formated as [id, server looked up, name server, IP address, rtype
    while True:
        if not adr:  # If was not found in cache
            if type(splitName) == list:  # If not looking for the domain name IP
                adr = get_dns_record(_sock, splitName[-1], params[0], params[1])
            else:  # if type(splitName) == str:  If looking for the domain name IP
                adr = get_dns_record(_sock, splitName, params[0], params[1], True)
                adr.insert(0, len(cache))  # Adds the id to the cache entry before adding to cache
                cache.append(adr)
                print(f'IP Address for {_domain_name}: {adr[3]}, resovled from authoritative name server\n')
                return
            if adr == None:  # Only happens if the query failed, becuase nothing was added to adr
                print(f'{_domain_name} is not a valid domain name\n')
                return
            if len(adr) == 4:  # Makes sure alias's are not added to the cache
                adr.insert(0, len(cache))  # Adds the id to the cache entry before adding to cache
                cache.append(adr)
        if len(splitName) == len(_domain_name.split(".")):  # If TLD name server
            params = [adr[3], adr[4]]  # Sets the parms to the TLD's IP and rtype
            # Combines to form the name server to be searched for by the TLD name server
            splitName[-2] = f'{splitName[-2]}.{splitName[-1]}'
            splitName.pop(-1)
            if not inCache:  # Above needs to happen regardless in order for the while loop to be in the correct state after cache
                print(f'{adr[1]} TLD name server consulted: {adr[2]}, obtained from root server')
        elif len(adr) == 2:  # If there is an Alias
            print(f'Alias for {_domain_name} found: {adr[1]}')
            return nameResolution(adr[1], _sock)  # Calls for another name resolution for the alias, and completes the name resolution of original domain name
        else:  # If Authoritative name server
            params = [adr[3], adr[4]]
            splitName = _domain_name  # Sets splitName to the domain name in order to search the authoritative name server for the domain name in the next loop
            if not inCache:  # Above needs to happen in order to get the loop into the correct state after cache
                print(f'{adr[1]} Authoritative name server consulted: {adr[2]}, obtained from TLD name server')
        # Resets at bottom instead of top, in order for the information passed in from the cache to stay in tact but to removed in the next loop
        adr = 0  
        inCache = False

            

def removeFromCache(toRemove):
    """
    toRemove: Item to be removed from the cache
    returns: None
    """
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

def checkCache(check:str, finished:bool):
    """
    check: The server to check if in the cache
    finished: If looking for the resolved IP Address
    returns: bool, adr[id, server looked up, name server, IP address, rtype]
    """
    for entry in cache:
        # If check is found in the cache
        if (check == entry[1] or f'{check}.' == entry[1]):
            # If it is looking for the resolved IP and there is no corresponding name server 
            # or If it is looking for a name server 
            # Prevents infinite loops
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
            if not validators.domain(domain_name):  # Checks to see if the domain name given is valid (mostly for commands)
                print(domain_name, " Is not a valid domain name or command\n")
            else:
                nameResolution(domain_name, sock)  # Calls the main function of DNS resolver

    sock.close()
