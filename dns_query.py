#!/usr/bin/env python

import argparse
import dns
import sys
import dns.resolver
import re
from os import path

ip_re = re.compile('.*?((?:[0-9]{1,3}\.){3}[0-9]{1,3})')


def resolve_ip(dns_server, domain):
    r = dns.resolver.Resolver()
    r.name_servers = [dns_server]
    try:
        query = r.query(domain, 'a')
    except dns.resolver.NXDOMAIN:
        return 'NXDOMAIN'

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

    # "DNS IP", "DNS DESC", "domain.com", "domain.com", ... \n
    output = '"DNS IP", "DNS DESC", ' + ','.join('"{}"'.format(domain) for domain in domain_list) + '\n'

    # "<dns ip>", "<dns desc>", "<ip>", "<ip>", ... \n
    for dns_ip, dns_desc in dns_list:
        output += '"{}", "{}", {}'.format(dns_ip, dns_desc.strip(),
                    ','.join('"{}"'.format(resolve_ip(dns_ip, domain)) for domain in domain_list)) + '\n'

    with open(args.output, 'w') as f:
        f.write(output)
