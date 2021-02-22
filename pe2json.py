#!/usr/bin/env python
#
#  pe2json v1.0
#
#  Copyright 2019-2021 Philippe Paquet
#
#  dependencies:
#      pefile
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#





#
#  Imports
#

import datetime
import json
import hashlib
import os
import sys



#
# Packages imports
#

if os.path.exists(os.path.abspath(os.path.join('.', 'packages'))):
	sys.path.insert(0, os.path.abspath(os.path.join('.', 'packages')));

try:
	import_pefile_failed = False
	import pefile
except ImportError:
	import_pefile_failed = True





#
#  defines
#

BLOCKSIZE = 65536





#
#  help_header
#

def help_header():
	print('')
	print('pe2json v1.0')
	print('Copyright 2019-2021 Philippe Paquet')



#
#  help_pefile
#

def help_pefile():
	help_header()
	print('')
	print('The pefile package by Ero Carrera is required')
	print('')
	print('    You can find pefile on github or pypi')
	print('        https://github.com/erocarrera/pefile')
	print('        https://pypi.org/project/pefile/')
	print('')
	print('    To install pefile using pip:')
	print('        pip install pefile')
	print('        python3 -m pip install pefile')
	print('')
	print('    If you want to keep everything within one directory, you can also install pefile in a "packages" subdirectory:')
	print('        pip install --target=packages pefile')
	print('        python3 -m pip install --target=packages pefile')
	print('')



#
#  help_arguments
#

def help_arguments():
	help_header()
	print('')
	print('Usage:      pe2json.py <input>')
	print('')
	print('            <input>     Either a filename or a directory')
	print('')
	print('                        If <input> is a file name, the JSON output will be optimized for readability')
	print('')
	print('                        If <input> is a directory name, the JSON output will be one line per file')
	print('')
	print('                        Only files with the following extensions will be considered for analysis for directories:')
	print('                        dll, drv, exe, sys')
	print('')
	print('Examples:   python3 pe2json.py C:\Windows\System32\kernel32.dll')
	print('            python3 pe2json.py C:\Windows\System32')
	print('')



#
#  pe_encoder
#

class pe_encoder(json.JSONEncoder):
	def default(self, obj):
		if isinstance(obj, (bytearray, bytes)):
			return obj.decode('UTF-8')
		if isinstance(obj, (date, datetime)):
			print(obj)
			return obj.timestamp()
		return json.JSONEncoder.default(self, obj)



#
#  analyze
#

def analyze(filepath, pretty):
	pe = pefile.PE(filepath)

	pe_dict = dict()

	# name
	pe_dict['name'] = os.path.basename(filepath)

	# size
	pe_dict['size'] = os.path.getsize(filepath)

	# md5, sha-1, sha-256, sha-512
	md5 = hashlib.md5()
	sha1 = hashlib.sha1()
	sha256 = hashlib.sha256()
	sha512 = hashlib.sha512()
	with open(filepath, 'rb') as file:
		buffer = file.read(BLOCKSIZE)
		while len(buffer) > 0:
			md5.update(buffer)
			sha1.update(buffer)
			sha256.update(buffer)
			sha512.update(buffer)
			buffer = file.read(BLOCKSIZE)
	pe_dict['md5'] = md5.hexdigest()
	pe_dict['sha-1'] = sha1.hexdigest()
	pe_dict['sha-256'] = sha256.hexdigest()
	pe_dict['sha-512'] = sha512.hexdigest()

	# imphash
	pe_dict['imphash'] = pe.get_imphash()

	# Add the whole pe to the dictionnary
	pe_dict.update(pe.dump_dict())

	# Make a json file
	if (pretty is True):
		pe_json = json.dumps(pe_dict, cls=pe_encoder, sort_keys=False, indent=4)
	else:
		pe_json = json.dumps(pe_dict, cls=pe_encoder, sort_keys=False)
	print(pe_json)

	pe.close()





#
#  main
#

if (import_pefile_failed is True):
	help_pefile()
	sys.exit()

if len(sys.argv) != 2:
	help_arguments()
	sys.exit()

if (os.path.isdir(sys.argv[1]) is True):
	for filename in os.listdir(sys.argv[1]):
		if filename.endswith(".dll") or filename.endswith(".drv") or filename.endswith(".exe") or filename.endswith(".sys"):
			analyze(os.path.join(sys.argv[1], filename), False)
elif (os.path.isfile(sys.argv[1]) is True):
	analyze(sys.argv[1], True)
else:
	help_arguments()
	sys.exit()
