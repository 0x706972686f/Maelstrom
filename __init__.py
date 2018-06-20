#!/usr/bin/python3

"""
Import Functions

Developed libraries can be found in the lib directory.
"""

from lib.fileAnalysis import fileAnalysis
from lib.executablefileAnalysis import executablefileAnalysis
from lib.officefileAnalysis import officefileAnalysis
from lib.virustotal import virustotal
import constants
from pathlib import Path
import exiftool
import argparse
import logging
import time
import json

"""
Function:     initLogging

Description:  
This function creates the log handler and file that the analysis will be written to.

Inputs:
        loggingfile (string) - The name of the file to write to 

Outputs:
        logger (log object) - The object handler for writing the output to.

"""
def initLogging(loggingfile):
        logger = logging.getLogger(__name__)
        logger.setLevel(logging.INFO)

        handler = logging.FileHandler(loggingfile)
        handler.setLevel(logging.INFO)

        formatter = logging.Formatter('%(message)s')
        handler.setFormatter(formatter)

        logger.addHandler(handler)

        return logger

"""
Function: genericfile

Description:
This is the default static analysis function for a file.

Inputs:
        filein (string) - The name and path of the file to analysise
        loggingfile (string) - The name of the logging file to print out to

Outputs:
        None
"""
def genericfile(filein,loggingfile):
        inputfile = filein

        try:
                print("[*] Attempting to Open the File")
                Path(inputfile).exists()
        except FileNotFoundError:
                print("[-] The file could not be found, please ensure you select a valid file.")
                sys.exit(1)

        else:

                print("[+] File present, commencing analysis - output logged to {}".format(loggingfile))
                logging = initLogging(loggingfile)
                f = fileAnalysis(inputfile)
                print("[+] Creating password infected zip")
                f.create_zip()
                logging.info('{:*^75s}\n'.format((time.strftime("%H:%M:%S %Y-%m-%d")+' - Starting File Analysis')))
                print("[+] Basic File Analysis")
                logging.info('{:30} {:<20}'.format('Filename:',f.filename))
                logging.info('{:30} {:<20}'.format('File Extension:',f.fileextension))
                logging.info('{:30} {:<20}'.format('Filesize (bytes):',f.filesize))
                logging.info('{:30} {:<20}'.format('Filesize (human):',f.get_filesizehuman()))
                print("[+] File Hashes")
                logging.info('{:30} {:<32}'.format('MD5 Hash:',f.md5hash))
                logging.info('{:30} {:<64}'.format('SHA 256 Hash:',f.sha256hash))
               
                print("[+] Retrieving file metadata")
                logging.info('\n{:*^75s}\n'.format('Start of File Metadata'))
                metadata = f.get_filemetadata()
                for k_m, v_m in metadata.items():
                        logging.info('{:<30} {:<50}'.format(k_m, v_m))

                print("[+] Checking MD5 Hash on Virustotal")
                vt = virustotal(constants.VIRUSTOTALAPI)
                vtjson = vt.submitmd5(f.md5hash)
                logging.info('\n{:*^75s}\n'.format('Start of VirusTotal JSON Results'))
                logging.info('{}'.format(json.dumps(vtjson, indent=4,sort_keys=True)))
                logging.info('\n{:*^75s}\n'.format('End of VirusTotal JSON Results'))
              
                print("[+] Checking against ClamAV")
                logging.info('{:30} {:<64}'.format('Clam AV Result: ',*f.get_clamavresult()))

                print("[*] Checking against Yara Rules - this may take a while")
                yarares = f.get_yararule()
                if yarares:
                        logging.info('\n{:*^75s}\n'.format('Start of YARA Rules'))
                        print("[+] Yara rules matched - writing output")
                        logging.info("{}".format(yarares))
                        logging.info('\n{:*^75s}\n'.format('End of YARA Rules'))
                else:
                        print("[-] Yara rules not matched")
                        logging.info('\n{:*^75s}\n'.format('No YARA Rules Matched'))
 
                print("[+] Determining Entropy of File")
                entropyinfo = f.get_fileentropy()

                logging.info('The smallest theoretical compressed file size (in bytes): {:.2f}'.format(entropyinfo['minfilesize']))
                logging.info('The smallest theoretical compressed file size (human): {:.2f}'.format(entropyinfo['minfilesizebyte'])) 
                logging.info('The efficiency indicates if the file has been packed, compressed or encrypted. A percentage of 50% represents normal text, which can be compressed. A percentage of 0% or 100% indicates that something has been compressed/encrypted/packed: {:.2f}%'.format(entropyinfo['efficiency']))
                logging.info('The Shannon Entropy represents the amount of bits it would take to represent a byte - this value is between 0 and 8. A value of 0 or 8 indicates that something has already been compressed/encrypted: {:.2f}'.format(entropyinfo['entropy']))
                logging.info('{:*^75s}'.format('End of File Metadata'))

                print("[+] Strings")
                logging.info('\n{:*^75s}\n'.format('Start of File Strings'))
                for string in f.get_strings():
                        logging.info('{}'.format(string))
                logging.info('\n{:*^75s}\n'.format('End of Strings'))
               
                """
                if f.fileextension.lower() in ['docx']:
                        print("[+] Microsoft Word Document Detected")
                        logging.info('\n{:*^75s}\n'.format('DOCX Detected - Retrieving URLs'))
                        d = officefileAnalysis(f.filename)
                        urls = d.get_docxurls()
                        print("[+] Scanning for URLs")
                        for url in urls:
                                logging.info('{}'.format(url))
                """

                print("[*] File Analysis complete - check {} for results".format(loggingfile))

""""
Function: executablefile

Description:
This is the static analysis function for executable file types, it conducts extra analysis such as dumping PE file information to provide further information.

Inputs:
        filein (string) - The name and path of the file to analysise
        loggingfile (string) - The name of the logging file to print out to

Outputs:
        None
"""
def executablefile(filein,loggingfile):
        inputfile = filein

        try:
                print("[*] Attempting to Open the File")
                Path(inputfile).exists()
        except FileNotFoundError:
                print("[-] The file could not be found, please ensure you select a valid file.")
                sys.exit(1)

        else:

                print("[+] File present, commencing analysis - output logged to {}".format(loggingfile))
                logging = initLogging(loggingfile)
                f = executablefileAnalysis(inputfile)
                f.create_zip()
                logging.info('{:*^75s}\n'.format((time.strftime("%H:%M:%S %Y-%m-%d")+' - Starting File Analysis')))
                print("[+] Basic File Analysis")
                logging.info('{:30} {:<20}'.format('Filename:',f.filename))
                logging.info('{:30} {:<20}'.format('File Extension:',f.fileextension))
                logging.info('{:30} {:<20}'.format('Filesize (bytes):',f.filesize))
                logging.info('{:30} {:<20}'.format('Filesize (human):',f.get_filesizehuman()))
                print("[+] File Hashes")
                logging.info('{:30} {:<32}'.format('MD5 Hash:',f.md5hash))
                logging.info('{:30} {:<64}'.format('SHA 256 Hash:',f.sha256hash))
               
                print("[+] Retrieving file metadata")
                logging.info('\n{:*^75s}\n'.format('Start of File Metadata'))
                metadata = f.get_filemetadata()
                for k_m, v_m in metadata.items():
                        logging.info('{:<30} {:<50}'.format(k_m, v_m))

                print("[+] Checking MD5 Hash on Virustotal")
                vt = virustotal(constants.VIRUSTOTALAPI)
                vtjson = vt.submitmd5(f.md5hash)
                logging.info('\n{:*^75s}\n'.format('Start of VirusTotal JSON Results'))
                logging.info('{}'.format(json.dumps(vtjson, indent=4,sort_keys=True)))
                logging.info('\n{:*^75s}\n'.format('End of VirusTotal JSON Results'))
                
                print("[+] Checking against ClamAV")
                logging.info('{:30} {:<64}'.format('Clam AV Result: ',*f.get_clamavresult()))

                print("[*] Checking against Yara Rules - this may take a while")
                yarares = f.get_yararule()
                if yarares:
                        logging.info('\n{:*^75s}\n'.format('Start of YARA Rules'))
                        print("[+] Yara rules matched - writing output")
                        logging.info("{}".format(yarares))
                        logging.info('\n{:*^75s}\n'.format('End of YARA Rules'))
                else:
                        print("[-] Yara rules not matched")
                        logging.info('\n{:*^75s}\n'.format('No YARA Rules Matched'))
 
                print("[+] Determining Entropy of File")
                entropyinfo = f.get_fileentropy()

                logging.info('The smallest theoretical compressed file size (in bytes): {:.2f}'.format(entropyinfo['minfilesize']))
                logging.info('The smallest theoretical compressed file size (human): {:.2f}'.format(entropyinfo['minfilesizebyte'])) 
                logging.info('The efficiency indicates if the file has been packed, compressed or encrypted. A percentage of 50% represents normal text, which can be compressed. A percentage of 0% or 100% indicates that something has been compressed/encrypted/packed: {:.2f}%'.format(entropyinfo['efficiency']))
                logging.info('The Shannon Entropy represents the amount of bits it would take to represent a byte - this value is between 0 and 8. A value of 0 or 8 indicates that something has already been compressed/encrypted: {:.2f}'.format(entropyinfo['entropy']))
                logging.info('{:*^75s}'.format('End of File Metadata'))

                print("[+] Hex Dump, Strings")
                logging.info('\n{:*^75s}\n'.format('Hex Dump (256 Bytes)'))
                logging.info('\n{}'.format(f.get_filehexdump()))
                logging.info('\n{:*^75s}\n'.format('Start of File Strings'))
                for string in f.get_strings():
                        logging.info('{}'.format(string))
                logging.info('\n{:*^75s}\n'.format('End of Strings'))
               
                print("[+] Executable Binary Detected - Determining PE Information")
                logging.info('\n{:*^75s}\n'.format('PE DLL Imports'))
                       
                print("[+] Determining DLL Imports and Functions")
                for entry in f.get_peimports():
                        for importfunction in entry.imports:
                            logging.info('DLL:  {} - Import Function: {}'.format(entry.dll,importfunction.name ))
                print("[+] Retrieving Sections and Sizes")
                logging.info('\n{:*^75s}\n'.format('PE Sections'))
                for section in f.get_pesections():
                        logging.info('Section: {} - Size (bytes): {}'.format(section.Name.decode("utf-8"),section.SizeOfRawData))
                print("[+] Dumping Entire PE")
                logging.info('\n{:*^75s}\n'.format('PE - Entire Dump'))
                logging.info('\n {}'.format(f.get_pedumpall()))
                print("[*] File Analysis complete - check {} for results".format(loggingfile))


"""
Function: identifyfiletype

Description:
This function uses the exiftool library to identify the magic file bit. The reason is that if I submitted `file.dat` for analysis, which is actually an executable binary (`file.exe`), this helps to ensure it goes to the correct function.

See the following for more information on the magic file bit:
https://en.wikipedia.org/wiki/List_of_file_signatures

Inputs:
        filename (string) - A string of the path and filename that is being submitted for analysis.

Outputs:
        None
"""
def identifyfiletype(filename):
        with exiftool.ExifTool() as et:
                metadata = et.get_metadata(filename)
        return metadata['File:FileTypeExtension']


"""
Function: main

Description:
The main function that determines what kind of analysis to run.

Inputs:
        args (args object) - The arguments that have been supplied to the function.

Outputs:
        None
"""
def main(args):
        if args.file is not None:
                filename = args.file
                extension = identifyfiletype(filename)
                loggingfile = constants.LOGGINGFILE
                if extension in ['EXE']:
                        executablefile(filename,loggingfile)
                elif extension in ['DOCX']:
                        genericfile(filename,loggingfile)
                else:
                        genericfile(filename,loggingfile)
"""
This function is the initialisation function, used for gathering the arguments that have been supplied.
"""
if __name__ == "__main__":
        parser = argparse.ArgumentParser()
        parser.add_argument('-f', '--file', type=str, help='Conduct analysis on a file.')
        parser.add_argument('-e', '--email', type=str, help='Conduct analysis on an email.')
        parser.add_argument('-n', '--network', type=str, help='Conduct analysis on a network component, such as a domain, a url or an ip address.')
        parser.add_argument('-p', '--packet', type=str, help='Conduct analysis on a packet capture.')
        #parser.add_argument("-d", "--detail", help="More detailed output", action="store_true")
        
        args = parser.parse_args()

        main(args)
