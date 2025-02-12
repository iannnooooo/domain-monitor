#!/usr/bin/env python3
"""Comprehensive Domain Monitor Script"""

import whois
import requests
import dns.resolver
import ssl
import socket
from datetime import datetime
import json


def check_ssl_certificate(domain):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            cert = s.getpeercert()
            expiry_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            return {'valid': True, 'expiry_date': expiry_date.strftime('%Y-%m-%d %H:%M:%S')}
    except Exception as e:
        return {'valid': False, 'error': str(e)}


def check_domain(domain):
    try:
        domain_info = whois.whois(domain)
        dns_records = {}
        for record_type in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                dns_records[record_type] = [str(answer) for answer in answers]
            except:
                dns_records[record_type] = []

        website_status = {}
        for protocol in ['http', 'https']:
            try:
                response = requests.get(f"{protocol}://{domain}", timeout=5)
                website_status[protocol] = response.status_code == 200
            except:
                website_status[protocol] = False

        ssl_info = check_ssl_certificate(domain)

        return {
            'domain': domain,
            'registrar': domain_info.registrar,
            'creation_date': str(domain_info.creation_date),
            'expiration_date': str(domain_info.expiration_date),
            'dns_records': dns_records,
            'website_status': website_status,
            'ssl_certificate': ssl_info
        }
    except Exception as e:
        return {'domain': domain, 'error': str(e)}


def main():
    domains = [
        'safaricom.net',
        'example.com'
    ]

    results = []
    for domain in domains:
        result = check_domain(domain)
        results.append(result)

    print("## Domain Monitor Results\n")
    for result in results:
        print(f"### {result['domain']}\n")
        if 'error' in result:
            print(f"**Error:** {result['error']}\n")
            continue

        print(f"- **Registrar:** {result['registrar']}")
        print(f"- **Creation Date:** {result['creation_date']}")
        print(f"- **Expiration Date:** {result['expiration_date']}")
        print(f"- **Website Active (HTTP):** {result['website_status']['http']}")
        print(f"- **Website Active (HTTPS):** {result['website_status']['https']}")

        if result['ssl_certificate']['valid']:
            print(f"- **SSL Expiry Date:** {result['ssl_certificate']['expiry_date']}")
        else:
            print(f"- **SSL Error:** {result['ssl_certificate']['error']}")

        print("\n**DNS Records:**")
        for record_type, records in result['dns_records'].items():
            if records:
                print(f"- {record_type}: {', '.join(records)}")
        print("\n---\n")

    # Save results to JSON file
    with open('domain_monitor_results.json', 'w') as f:
        json.dump(results, f, indent=4)


if __name__ == "__main__":
    main()
