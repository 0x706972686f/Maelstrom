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
Object: executablefileAnalysis (inherits from fileAnalysis)

Functions:
        get_filehexdump - generates a hexdump of a file
        get_pesections - reports the size in bytes of the sections within a PE file
        get_pedumpall - dumps the entire contents of a PE binary
        get_peimports - reports the DLL files and the function calls that have been imported

'''

class executablefileAnalysis(fileAnalysis):
        def __init__(self,filepath):
                fileAnalysis.__init__(self,filepath)

        def get_filehexdump(self):
                with open(self.filepath, 'rb') as f:
                        data = f.read()
                return self.hexdump(data)

        def get_pesections(self):
                pe = pefile.PE(self.filepath)
                return pe.sections

        def get_pedumpall(self):
                pe = pefile.PE(self.filepath)
                return pe.dump_info()

        def get_peimports(self):
                pe = pefile.PE(self.filepath)
                return pe.DIRECTORY_ENTRY_IMPORT


