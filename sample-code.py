from dnslib import DNSRecord, DNSHeader, DNSBuffer, DNSQuestion, RR, QTYPE, RCODE
from socket import socket, SOCK_DGRAM, AF_INET
import validators

"""
There are 13 root servers defined at https://www.iana.org/domains/root/servers
"""

ROOT_SERVER = "199.7.83.42"    # ICANN Root Server
DNS_PORT = 53
def get_dns_record(udp_socket, domain:str, parent_server: str, record_type):
  q = DNSRecord.question(domain, qtype = record_type)
  q.header.rd = 0   # Recursion Desired?  NO **DO NOT CHANGE**
  print("DNS query", repr(q))
  udp_socket.sendto(q.pack(), (parent_server, DNS_PORT))
  pkt, _ = udp_socket.recvfrom(8192)
  buff = DNSBuffer(pkt)
  
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
  print("DNS header", repr(header))
  if q.header.id != header.id:
    print("Unmatched transaction")
    return
  if header.rcode != RCODE.NOERROR:
    print("Query failed")
    return

  # Parse the question section #2
  for k in range(header.q):
    q = DNSQuestion.parse(buff)
    print(f"Question-{k} {repr(q)}")
    
  # Parse the answer section #3
  for k in range(header.a):
    a = RR.parse(buff)
    print(f"Answer-{k} {repr(a)}")
    if a.rtype == QTYPE.A:
      print("IP address")
      
  # Parse the authority section #4
  for k in range(header.auth):
    auth = RR.parse(buff)
    print(f"Authority-{k} {repr(auth)}")
  
  return_adr = "0.0.0.0"
  # Parse the additional section #5
  for k in range(header.ar):
    adr = RR.parse(buff)
    print(f"Additional-{k} {repr(adr)} Name: {adr.rname}")
    #print(adr.r)
  # return something with addition section 
  # adr.rdata is the IP address
  # adr.rtype is the type of data A=IPv4, AAAA=IPv6, NS=Host Name, CNAME=Domain Name
  return 
  
if __name__ == '__main__':
  # Create a UDP socket
  sock = socket(AF_INET, SOCK_DGRAM)
  sock.settimeout(2)
  cache = []
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
          print(".remove #: Removes the specificed cache entry")
      elif domain_name == ".list":
          print(cache) # Implement for List of lists with 3 values
      elif domain_name == ".clear":
          cache = []
      elif domain_name.startswith(".remove"):
          try:
              num = domain_name.split(" ")
              for i in cache:
                  if i[0] == num:
                      cache.remove(i)
          except: # add exceptions
              pass
      else:
          while True:
              # Use the function to get_dns_record(__) to resovlve the IP address of the domain name
              if not validators.domain(domain_name):
                  print(domain_name, " Is not a valid domain name or command")
                  break
              print("loop") 
              adr = get_dns_record(sock, domain_name, ROOT_SERVER, "NS")
              adr2 = get_dns_record(sock, domain_name, adr, "NS")
              break


  # Get all the .edu name servers from the ROOT SERVER
  #  get_dns_record(sock, "edu", ROOT_SERVER, "NS") The picture in the repo
  
  # The following function calls are FAILED attempts to use Google Public DNS
  # (1) to get name servers which manages gvsu.edu
  # (2) to resolve the IP address of www.gvsu.edu
  # get_dns_record(sock, "gvsu.edu", "8.8.8.8", "NS")      # (1)
  # get_dns_record(sock, "www.gvsu.edu", "8.8.8.8", "A")   # (2)
  
  sock.close()