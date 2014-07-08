#!/usr/bin/env python

import argparse
import dns
import sys
import dns.resolver
import re
import csv
from os import path
from gevent import monkey
monkey.patch_all()
from gevent.pool import Pool
from random import shuffle

ip_re = re.compile('.*?((?:[0-9]{1,3}\.){3}[0-9]{1,3})')


def resolve_ip(dns_server, domain):
    print("Resolving {} against DNS server {} ...".format(domain, dns_server))
    r = dns.resolver.Resolver()
    r.lifetime = 5  # timeout
    r.name_servers = [dns_server]
    try:
        query = r.query(domain, 'a')
    except dns.resolver.NXDOMAIN:
        return 'NXDOMAIN'
    except dns.exception.Timeout:
        return 'TIMEOUT'
    except dns.resolver.NoNameservers:
        return 'NO NAMESERVERS'

    response = query.response.to_text().split('\n')
    # 'id 64407\nopcode QUERY\nrcode NOERROR\nflags QR RD RA\n;QUESTION\npython.org. IN A\n;ANSWER\npython.org. 1383 IN A 140.211.10.69\n;AUTHORITY\n;ADDITIONAL'

    try:
        answer_index = response.index(';ANSWER')
    except ValueError:
        return 'error extracting answer'

    ip_match = ip_re.match(response[answer_index+1])

    try:
        return ip_match.group(1)
    except IndexError:
        return 'error extracting ip'


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DNS A record multi-lookup")
    parser.add_argument('domain_list',
                        help='File containing a newline separated list of domains to lookup A-records for')
    parser.add_argument('dns_list',
                        help='File containing a newline separated list of <dns ip> <dns description>')
    parser.add_argument('output',
                        help='Output file (does not prompt to overwrite)')
    args = parser.parse_args()

    domain_list_file = args.domain_list
    if not path.exists(domain_list_file):
        print('Domain list does not exist')
        sys.exit()

    with open(domain_list_file) as f:
        domain_list = [s.strip() for s in f.read().split('\n') if s.count('.') > 0]

    dns_list_file = args.dns_list
    if not path.exists(dns_list_file):
        print('DNS list does not exist')
        sys.exit()

    with open(dns_list_file) as f:
        dns_list = [s.split(' ', 1) for s in f.read().split('\n') if s.count(' ') > 0]

    worker_pool = Pool(50)
    work = []
    for domain in domain_list:
        for dns_ip, dns_desc in dns_list:
            work.append((dns_ip, domain))
    shuffle(work)
    # Build up a list of (dns_ip, domain) to check, in random order

    def wrap_work(inp):
        # Takes a tuple of (dns_ip, domain) and returns (dns_ip, domain, resolved ip)
        dns_ip, domain = inp
        return dns_ip, domain, resolve_ip(dns_ip, domain)

    results = {}
    for dns_ip, domain, ip in worker_pool.imap_unordered(wrap_work, work):
        results[(dns_ip, domain)] = ip
        # Apply wrap_work to every item in work then store the results in a dict

    # "<dns ip>", "<dns desc>", "<ip>", "<ip>", ... \n
    out = csv.writer(open(args.output, 'wb'))
    out.writerow(["DNS IP", "DNS DESC"] + domain_list)
    for dns_ip, dns_desc in dns_list:
        # Look up and format every combination of dns and domain
        out.writerow([dns_ip, dns_desc.strip()] + list(results[(dns_ip, domain)] if (dns_ip, domain) in results else "unknown" for domain in domain_list))
