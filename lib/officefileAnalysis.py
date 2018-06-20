#!/usr/bin/python3

"""
Script Description
"""

from lib.fileAnalysis import fileAnalysis
import constants
import pefile
import sys
import hashlib
import pathlib
import os
import base64
import string
import zipfile
import pyminizip
import re
import exiftool
import math
import clamd
import yara
import ntpath

'''
Object: officefileAnalysis (inherits from fileAnalysis)

Functions:
        get_docxurls - A Word .docx file is actually an archive, this opens the archive and reads the metadata, searching for URLs - it won't report what the URL looks like, just the actual URL underneath
        get_docxmeta - Work in Progress
        get_docxmacro - Work in Progress
        get_docximage - Retrieves image file formats from within the archive, and writes them to a file
'''

class officefileAnalysis(fileAnalysis):
        def __init__(self,filepath):
                fileAnalysis.__init__(self,filepath)

        def get_docxurls(self):
                result = []
                
                zipf = zipfile.ZipFile(self.filepath)
                filelist = zipf.namelist()

                """
                Hypertext URLs are displayed in two ways in Microsoft Office XML
                -The display text is shown in word/document.xml (what the user can read)
                -The actual URL is shown in word/_rels/document.xml.rels

                Image URLs are also shown in word/_rels/document.xml.rels
                """
                doc_xml = 'word/_rels/document.xml.rels'
                text = zipf.read(doc_xml).decode('utf-8')
                urls = re.findall('https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+', text)

                microsofturls = ['http://schemas.openxmlformats.org','http://schemas.microsoft.com']
                
                for url in urls:
                        if url not in microsofturls:
                                result.append(url)

                #docPros/core.xml - has all the metadata

                zipf.close()
                return result

        def get_docxmeta(self):
                pass

        def get_docmmacro(self):

                #vba.bin or oletools
                pass

        def get_docximage(self):
                # Grabs Images
                for f in filelist:
                        _, extension = os.path.splitext(f)
                        if extension in ['.jpg', '.jpeg', '.png', '.bmp']:
                                with open(f, 'wb') as outimage:
                                        outimage.write(zipf.read(f))

