#! /usr/bin/python3

import requests
import datetime 
import argparse

#Colors
class Colors:
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    PURPLE = '\033[95m'
    ENDC = '\033[0m'


#VirusTotal API Key
API_KEY = " "           ###### PUT API KEY HERE ######
#Not Available
NA = "Not Available"
#Divider
DIVIDER = "=" * 90
#Security Vendors' Analysis
SECURITY_VENDORS_ANALYSIS = "SECURITY VENDORS' ANALYSIS"
#BASIC PROPERTIES
BASIC_PROPERTIES = "BASIC PROPERTIES"
#HISTORY
HISTORY = "HISTORY"
#No Matches Found
NO_MATCHES_FOUND = Colors.RED + "NO MATCHES FOUND" + Colors.ENDC
#ERROR
ERROR = Colors.RED + "ERROR" + Colors.ENDC
#CONNECTION ERROR
CONNECTION_ERROR = "CONNECTION ERROR"


class VirusTotal:
    def __init__(self):
        self.headers = {"accept": "application/json","X-Apikey": API_KEY}
        self.url = "https://www.virustotal.com/api/v3/"

    def upload_hash(self, hash):
        url = self.url + "search?query=" + hash
        response = requests.get(url, headers=self.headers)
        result = response.json()
        if response.status_code == 200 and len(result['data']) > 0:
            try:
                malicious = result['data'][0]['attributes']['last_analysis_stats']['malicious']      #pulls the total number of vendors who identified hash as malicious
            except:
                malicious = 0
            try:
                undetected = result['data'][0]['attributes']['last_analysis_stats']['undetected']     #pulls the total number of vendors who did not detect hash
            except:
                undetected = 0
            try:
                meaningful_name = result['data'][0]['attributes']['meaningful_name']        #pulls meaningful_name
            except:
                meaningful_name = NA
            try:
                md5 = result['data'][0]['attributes']['md5']        #pulls md5 hash
            except:
                md5 = NA
            try:
                sha1 = result['data'][0]['attributes']['sha1']      #pulls sha1 hash
            except:
                sha1 = NA
            try:
                sha256 = result['data'][0]['attributes']['sha256']      #pulls sha256 hash
            except:
                sha256 = NA
            try:
                vhash = result['data'][0]['attributes']['vhash']      #pulls Vhash
            except:
                vhash = NA
            try:
                authentihash = result['data'][0]['attributes']['authentihash']      #pulls Authentihash
            except:
                authentihash = NA
            try:
                imphash = result['data'][0]['attributes']['pe_info']['imphash']      #pulls Imphash
            except:
                imphash = NA
            try:
                rich_pe_header_hash = result['data'][0]['attributes']['pe_info']['rich_pe_header_hash']      #pulls Rich PE Header Hash
            except:
                rich_pe_header_hash = NA
            try:
                ssdeep = result['data'][0]['attributes']['ssdeep']      #pulls SSDEEP
            except:
                ssdeep = NA
            try:
                tlsh = result['data'][0]['attributes']['tlsh']      #pulls TLSH
            except:
                tlsh = NA
            try:
                type = result['data'][0]['type']      #pulls type of file
            except:
                type = NA
            try:
                type_description = result['data'][0]['attributes']['type_description']      #pulls type of file
            except:
                type_description = NA
            try:
                magic = result['data'][0]['attributes']['magic']      #pulls Magic
            except:
                magic = NA
            try:
                size = result['data'][0]['attributes']['size']      #pulls size of file
            except:
                size = "Unknown"
            try:
                first_seen_in_the_wild = datetime.datetime.fromtimestamp( result['data'][0]['attributes']['first_seen_itw_date'])     #converts epoch time into DateTime. This is for "first seen in the wild"
            except:
                first_seen_in_the_wild = NA
            try:
                last_analysis_date = datetime.datetime.fromtimestamp(result['data'][0]['attributes']['last_analysis_date'])      #pulls the last analysis date
            except:
                last_analysis_date = NA
            try:
                first_submission_date = datetime.datetime.fromtimestamp(result['data'][0]['attributes']['first_submission_date'])      #pulls the first submission date
            except:
                first_submission_date = NA
            try:
                last_submission_date = datetime.datetime.fromtimestamp(result['data'][0]['attributes']['last_submission_date'])       #pulls the creation date
            except:
                last_submission_date = NA
            try:
                creation_date = datetime.datetime.fromtimestamp(result['data'][0]['attributes']['creation_date'])      #pulls the creation date
            except:
                creation_date = NA

            

            print(DIVIDER)
            print(f"{SECURITY_VENDORS_ANALYSIS : ^90}")
            print(DIVIDER)
            print(f"{'Total Vendors' : <30}" + str(malicious + undetected))
            print(f"{'Malicious' : <30}" + str(malicious))
            print(f"{'Undetected' : <30}" + str(undetected))

            print(DIVIDER)
            print(f"{BASIC_PROPERTIES : ^90}")
            print(DIVIDER)
            print(f"{'Name' : <30}" + meaningful_name)
            print(f"{'md5' : <30}" + md5)
            print(f"{'sha1' : <30}" + sha1)
            print(f"{'sha256' : <30}" + sha256)
            print(f"{'Vhash' : <30}" + vhash)
            print(f"{'Authentihash' : <30}" + authentihash)
            print(f"{'Imphash' : <30}" + imphash)
            print(f"{'Rich PE header hash' : <30}" + rich_pe_header_hash)
            print(f"{'SSDEEP' : <30}" + ssdeep)
            print(f"{'TLSH' : <30}" + tlsh)
            print(f"{'Type' : <30}" + type)
            print(f"{'Type Description' : <30}" + type_description)
            print(f"{'Magic' : <30}" + magic)
            print(f"{'File size' : <30}" + str(size) + " bytes")

            print(DIVIDER)
            print(f"{HISTORY : ^90}")
            print(DIVIDER)
            print(f"{'Creation Time' : <30}" + str(creation_date))
            print(f"{'First Seen In The Wild' : <30}" + str(first_seen_in_the_wild))
            print(f"{'First Submission Date' : <30}" + str(first_submission_date))
            print(f"{'Last Submission Date' : <30}" + str(last_submission_date))
            print(f"{'Last Analysis Date' : <30}" + str(last_analysis_date))
        
        elif response.status_code == 200 and len(result['data']) < 1:
            print(DIVIDER)
            print(f"{NO_MATCHES_FOUND : ^90}")
            print(DIVIDER)
        
        elif response.status_code == 401 and 'error' in result.keys():
            try:
                message = result['error']['message']        #pulls error message
            except:
                message = ERROR
            try:
                code = result['error']['code']      #pulls error code
            except:
                message = ERROR

            print(DIVIDER)
            print(f"{ERROR : ^90}")
            print(DIVIDER)

            print(f"{'Message' : <30}" + message)
            print(f"{'Code' : <30}" + code)
        
        else:
            print(DIVIDER)
            print(f"{ERROR : ^90}")
            print(DIVIDER)
            print(f"{'Message' : <30}" + CONNECTION_ERROR)

    def upload_ip(self, IP):
        url = self.url + "search?query=" + IP
        response = requests.get(url, headers=self.headers)
        result = response.json()
        if response.status_code == 200 and len(result['data']) > 0:
            try:
                malicious = result['data'][0]['attributes']['last_analysis_stats']['malicious']      #pulls the number of vendors who deem this IP malicious
            except:
                malicious = 0
            try:
                harmless = result['data'][0]['attributes']['last_analysis_stats']['harmless']       #pulls the number of vendors who deem this IP harmless
            except:
                harmless = 0
            try:
                suspicious = result['data'][0]['attributes']['last_analysis_stats']['suspicious']     #pulls the number of vendors who deem this IP suspicious
            except:
                suspicious = 0
            try:
                undetected = result['data'][0]['attributes']['last_analysis_stats']['undetected']     #pulls the total number of vendors who did not detect IP
            except:
                undetected = 0    
            try:
                country = result['data'][0]['attributes']['country']       #pulls the country of the IP
            except:
                undetected = NA  
            try:
                as_owner = result['data'][0]['attributes']['as_owner']      #pulls the Autonomous System Label
            except:
                as_owner = NA
            try:
                regional_internet_registry = result['data'][0]['attributes']['regional_internet_registry']      #pulls the regional internet registry
            except:
                regional_internet_registry = NA
            try:
                asn = result['data'][0]['attributes']['asn']      #pulls the Autonomous System Number
            except:
                asn = NA
            try:
                network = result['data'][0]['attributes']['network']        #pulls the network
            except:
                network = NA
            try:
                continent = result['data'][0]['attributes']['continent']        #pulls the continent
            except:
                continent = NA
            try:
                tags = result['data'][0]['attributes']['tags'][0]        #pulls the tags
            except:
                tags = NA
            try:
                last_analysis_date = datetime.datetime.fromtimestamp(result['data'][0]['attributes']['last_analysis_date'])        #pulls the whois date
            except:
                last_analysis_date = NA
            try:
                last_modification_date = datetime.datetime.fromtimestamp(result['data'][0]['attributes']['last_modification_date'])        #pulls the whois date
            except:
                last_modification_date = NA
            try:
                whois_date = datetime.datetime.fromtimestamp(result['data'][0]['attributes']['whois_date'])        #pulls the whois date
            except:
                whois = NA
            try:
                whois = result['data'][0]['attributes']['whois']        #pulls the whois
            except:
                whois = NA
            try:
                type = result['data'][0]['type']        #pulls the type
            except:
                type = NA

            print(DIVIDER)
            print(f"{SECURITY_VENDORS_ANALYSIS : ^90}")
            print(DIVIDER)
            print(f"{'Malicious' : <30}" + str(malicious))
            print(f"{'Harmless' : <30}" + str(harmless))
            print(f"{'Suspicious' : <30}" + str(suspicious))
            print(f"{'Undetected' : <30}" + str(undetected))

            print(DIVIDER)
            print(f"{BASIC_PROPERTIES : ^90}")
            print(DIVIDER)
            print(f"{'Type' : <30}" + type)
            print(f"{'Tags' : <30}" + tags)
            print(f"{'Network' : <30}" + network)
            print(f"{'Autonomous System Number' : <30}" + str(asn))
            print(f"{'Autonomous System Label' : <30}" + str(as_owner))
            print(f"{'Regional Internet Registry' : <30}" + regional_internet_registry)
            print(f"{'Country' : <30}" + country)
            print(f"{'Continent' : <30}" + continent)

            print(DIVIDER)
            print(f"{HISTORY : ^90}")
            print(DIVIDER)
            print(f"{'Last Analysis Date' : <30}" + str(last_analysis_date))
            print(f"{'Last Modification Date' : <30}" + str(last_modification_date))

            print(DIVIDER)
            print(f"{'WHOIS LOOKUP' : ^90}")
            print(DIVIDER)
            print(f"{'Whois Date' : <30}" + str(whois_date))
            print("")
            print(f"{whois}")

        elif response.status_code == 200 and len(result['data']) < 1:
            print(DIVIDER)
            print(f"{NO_MATCHES_FOUND : ^90}")
            print(DIVIDER)

        elif response.status_code == 401 and 'error' in result.keys():
            try:
                message = result['error']['message']        #pulls error message
            except:
                message = ERROR
            try:
                code = result['error']['code']      #pulls error code
            except:
                message = ERROR

            print(DIVIDER)
            print(f"{ERROR : ^90}")
            print(DIVIDER)
            print(f"{'Message' : <30}" + message)
            print(f"{'Code' : <30}" + code)
        
        else:
            print(DIVIDER)
            print(f"{ERROR : ^90}")
            print(DIVIDER)
            print(f"{'Message' : <30}" + CONNECTION_ERROR)


    def run(self, args):

        if args['IP']:
            virustotal.upload_ip(args['IP'])
        elif args['hash']:
            virustotal.upload_hash(args['hash'])



if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-H', '--hash', help = "Hash for scanning")
    parser.add_argument('-ip', '--IP', help = "IP Address for scanning")
    args = vars(parser.parse_args())
    virustotal = VirusTotal()
    virustotal.run(args)