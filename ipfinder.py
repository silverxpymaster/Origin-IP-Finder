import requests
import argparse
import json
from termcolor import colored

print(colored(r""" 
   _______    _____         __       
  /  _/ _ \  / __(_)__  ___/ /__ ____
 _/ // ___/ / _// / _ \/ _  / -_) __/
/___/_/    /_/ /_/_//_/\_,_/\__/_/   
          
     
         Author: SilverX        Tg: t.me/silverxvip                           
""",'red'))


def virustotal_iplerini_al(domain, api_acari):
    url = f"https://www.virustotal.com/vtapi/v2/domain/report?domain={domain}&apikey={api_acari}"
    cavab = requests.get(url)
    if cavab.status_code == 200:
        melumat = cavab.json()
        return melumat.get("resolutions", [])
    return []

def alienvault_iplerini_al(domain):
    url = f"https://otx.alienvault.com/api/v1/indicators/hostname/{domain}/url_list?limit=500&page=1"
    cavab = requests.get(url)
    if cavab.status_code == 200:
        melumat = cavab.json()
        return [giris.get("result", {}).get("urlworker", {}).get("ip") for giris in melumat.get("url_list", []) if giris.get("result", {}).get("urlworker", {}).get("ip")]
    return []

def urlscan_iplerini_al(domain):
    url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=1000"
    cavab = requests.get(url)
    if cavab.status_code == 200:
        melumat = cavab.json()
        return [giris.get("page", {}).get("ip") for giris in melumat.get("results", []) if giris.get("page", {}).get("ip")]
    return []

def ipleri_fayla_yaz(ipler, fayl_adi="ip.txt"):
    with open(fayl_adi, "w") as f:
        for ip in ipler:
            if ip:
                f.write(ip + "\n")
    print(f"IP addresses have been written to the file {fayl_adi}.")

def esas():
    parser = argparse.ArgumentParser(description="Origin IP Finder")
    parser.add_argument("-d", "--domain", required=True, help="Enter the target domain")
    args = parser.parse_args()
    
    api_acari = input("VirusTotal API Key: ")
    
    print("[*] Collecting IP addresses...")
    vt_ipler = [giris["ip_address"] for giris in virustotal_iplerini_al(args.domain, api_acari) if "ip_address" in giris]
    av_ipler = alienvault_iplerini_al(args.domain)
    us_ipler = urlscan_iplerini_al(args.domain)
    
    butun_ipler = list(set(vt_ipler + av_ipler + us_ipler))
    for ip in butun_ipler:
        print(ip)
    
    ipleri_fayla_yaz(butun_ipler)

if __name__ == "__main__":
    esas()
