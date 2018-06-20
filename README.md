# Maelstrom v0.1

## About
Maelstrom is an Alpha tool to help incident responders automate the static analysis of malware. While tools like CuckooBox conduct dynamic analysis of malware samples, I was finding that I'd run the same few basic commands time and time again. 

I decided to use this as an opportunity to not only automate the commands through python, but also to attempt to improve and provide further information to make analysis easier and quicker.

After commencing, I later discovered [Viper](https://github.com/viper-framework/viper), but decided to continue with the development in my spare time in an attempt to further my own knowledge and improve my programming. I'd suggest Viper as a more developed tool for serious incident response.

## Install:
The following _should_ install all requirements:
```
sudo apt-get install python3 pip3 clamav-daemon clamav-freshclam clamav-unofficial-sigs libmagic libmagic-dev openssl openssl-dev libssl-dev zlib
pip3 install requirements.txt
```
Please note that this has been developed for python3 exclusively.

## Startup Commands:
Ensure ClamAV is running and up to date:
```
sudo service clamav-daemon start
sudo freshclam
```

## Usage:

```
$ ./__init__.py -f /path/to/file
$ python3 __init__.py --file /path/to/file
```

## Current Features:
The script currently will do the following:
- Show File Size
- Generate Hashes (MD5, SHA256)
- Determine the file type using the file magic bit
- Display file metadata
- Query VirusTotal and return detailed JSON results
- Query ClamAV and if matched return details JSON results
- Query YARA rules and report any matches
- Determine the entropy of the file (to identify if the file is compressed/encrypted/packed)
- Hex Dump of the File
- Search for strings in the file
- For portable executables will list the DLL's imported and the Windows API functions queried
- Outline the PE Sections and their size in bytes
- Dump the entire PE
- Retrieve URLs from Office documents
- Save images from Office Documents
- Create a report of the analysis
- Create a password protected zip file of the malware for safe handling

## Planned Additions:
The end goal will be a two stage option, the first will be a python script that can be run to analyse a file, the second stage is a web based flask application that can be queried through an API, or uploaded through a web interface.

The planned features for the script include:
- Use headless chrome:
  - Browse to a domain
  - Display the HTML, JS and CSS of the page
  - Identify cookies
  - Identify URL referrers
  - Take a screenshot
  - Accept multiple user agents (including desktop and mobile user agents)
  - Download malicious files and analyse
- Query the following domains for a submitted URL to gather further information:
  - haveibeenpwned.com
  - phish.io
  - Shodan API
  - MISP
  - ExploitDB
- Use NMAP to query an IP Address/Domain for basic ports
- Gather basic IP/Network Domain and Network Whois information and DNS records
- Submit Emails (either through forwarding to an email server, or by submitting an email file)
  - Retrieve header information
  - Retrieve URLs and investigate
  - Retrieve Attachments and analyse
- Conduct analysis on further file types
- Submit packet captures
  - Retrieve files 
  - Run [JA3](https://github.com/salesforce/ja3/blob/master/python/ja3/ja3.py) over the packet capture
  - Identify domains and analyse

For the web application, I'd like to include the following:
- Develop an API so that users can query
- Integrate with twitter to report
- Conduct fuzzy hashing to identify other malware
- A search index for easy discovery
- Tagging to identify
- Sample repository for further analysis in the future.

## Potential Future Development:
- Integrate with Cuckoo box for sandbox deployment
  - Take a tcpdump of all traffic
  - Run [JA3](https://github.com/salesforce/ja3/blob/master/python/ja3/ja3.py) over the packet capture
- Conduct basic deobfuscation of files/javascript
- Microsoft Binary Signature reporting and verifying (sigcheck)
