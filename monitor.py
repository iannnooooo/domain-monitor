#!/usr/bin/env python3
"""Domain Monitor Script"""
import whois
import requests
import dns.resolver
from datetime import datetime
import json
import os

def check_domain(domain):
    try:
        domain_info = whois.whois(domain)
        dns_records = {}
        for record_type in ['A', 'MX', 'NS']:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                dns_records[record_type] = [str(answer) for answer in answers]
            except:
                dns_records[record_type] = []

        try:
            response = requests.get(f"http://{domain}", timeout=5)
            website_active = response.status_code == 200
        except:
            website_active = False

        return {
            'domain': domain,
            'registrar': domain_info.registrar,
            'creation_date': str(domain_info.creation_date),
            'dns_records': dns_records,
            'website_active': website_active
        }
    except Exception as e:
        return {'domain': domain, 'error': str(e)}

def main():
    # Add your target domain variations here
    domains = [
        'safaricom.net'
    ]

    results = []
    for domain in domains:
        result = check_domain(domain)
        results.append(result)

    # Print results in markdown format
    print("## Domain Monitor Results\n")
    for result in results:
        print(f"### {result['domain']}\n")
        if 'error' in result:
            print(f"Error: {result['error']}\n")
            continue

        print(f"- Registrar: {result['registrar']}")
        print(f"- Creation Date: {result['creation_date']}")
        print(f"- Website Active: {result['website_active']}")
        print("\nDNS Records:")
        for record_type, records in result['dns_records'].items():
            if records:
                print(f"- {record_type}: {', '.join(records)}")
        print("\n---\n")

if __name__ == "__main__":
    main()
