#!/usr/bin/python3 
import os
import datetime
import requests
import json

'''
Object: virustotal

Functions:
        decipherresponse - Uses the HTTP GET response code to verify that the query was successful
        submitfile - Uploads a file to VirusTotal for analysis
        submitmd5 - Queries an MD5 hash in virustotal for any existing matches
        submiturl - Submits a URL for analysis in VirusTotal
        queryurl - Searches VirusTotal for a URL and reports the results
        queryip - Searches VirusTotal for an IP address and reports the results
        querydomain - Searches VirusTotal for a domain, and reports the results
'''

class virustotal(object):
        def __init__(self, apikey):
                self.apikey = apikey
                self.url = 'https://www.virustotal.com/vtapi/v2/'
                if apikey is None:
                        raise ApiError("A valid VirusTotal API Key is required")

        @staticmethod
        def decipherresponse(response, jsonresults=True):
                #
                # Problem with the requests.code.ok
                #
                if response.status_code == requests.codes.ok:
                        return dict(results=response.json() if jsonresults else response.content, response_code=response.status_code)
                elif response.status_code == 400:
                        return dict(error='Malformed Query - HTTP Response Code: ',response_code=response.status_code)
                elif response.status_code == 204:
                        return dict(error='The public API request rate of 4 requests of per minute have been exceeded - HTTP Response Code: )',response_code=response.status_code)
                elif response.status_code == 403:
                        return dict(error='You attempting to query a private API function - HTTP Response Code: ',response_code=response.status_code)
                elif response.status_code == 404:
                        return dict(error='File not found - HTTP Response Code: ', response_code=response.status_code)
                else:
                        return dict(response_code=response.status_code)

        def submitfile(self, filename):
                params = {'apikey': self.api_key}
                submitfile = {'file': (filename, open(filename, 'rb').read())}

                try:
                       response = requests.post(self.url + 'file/scan', submitfile, params=params, proxies=None, timeout=300)
                except requests.RequestException as e:
                        return dict(error=str(e))

                return decipherresponse(response)


        def submitmd5(self,md5sum):
                params = {'apikey': self.apikey, 'resource': md5sum}

                try:
                        response = requests.post(self.url + 'file/report', params=params, proxies=None, timeout=300)
                except requests.RequestException as e:
                        return dict(error=str(e))

                return self.decipherresponse(response)

        def submiturl(self, url):
                params = {'apikey': self.apikey, 'url': url}

                try:
                        response = requests.post(self.url + 'url/scan', params=params, proxies=None, timeout=300)
                except requests.RequestException as e:
                        return dic(error=str(e))

                return decipherresponse(response)


        def queryurl(self, url):
                params = {'apikey': self.apikey, 'resource': url, 'scan': 0}

                try:
                        response = requests.get(self.url + 'url/report', params=params, proxies=None, timeout=300)
                except requests.RequestException as e:
                        return dict(error=str(e))

                return decipherresponse(response)

        def queryip(self, ip):
                params = {'apikey': self.apikey, 'ip': ip}

                try:
                        response = requests.get(self.url + 'ip-address/report', params=params, proxies=None, timeout=300)
                except requests.RequestException as e:
                        return dict(error=str(e))

                return decipherresponse(response)

        def querydomain(self, domain):
                params = {'apikey': self.apikey, 'domain': domain}

                try:
                        response = requests.get(self.url + 'domain/report', params=params, proxies=None, timeout=300)
                except requests.RequestException as e:
                        return dict(error=str(e))

                return decipherresponse(response)
