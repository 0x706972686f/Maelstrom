# Imports
import time
import os

# Logging text file name
LOGGINGFILE = time.strftime('%Y-%m-%d-%H:%M:%S') + '-results.txt'

# Default location for the yara rules
DEFAULTYARARULE = 'yararules/index.yar'

# Minimum string lengths to use when running 'strings' 
MINIMUMSTRINGLENGTH = 8

# Creating a zip for the infected
ZIPNAME = 'malware.zip'
ZIPPASSWORD = 'infected'

# VirusTotal API Key - if not set will throw an exception
VIRUSTOTALAPI = ''

# Headless Chrome Settings
CHROMEDRIVERPATH = os.getcwd() + '/lib/chromedriver-nix-x64-2.39'
DESKTOPUSERAGENT = 'user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.89 Safari/537.36'
MOBILEUSERAGENT = 'user-agent=Mozilla/5.0 (Linux; Android 6.0.1; SM-G532G Build/MMB29T) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.83 Mobile Safari/537.36'
