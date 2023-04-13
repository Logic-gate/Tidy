# -*- coding: utf-8 -*-

# Copyright (C) 2022 Logic-Gate
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""Tidy Encryption Scheme"""

__author__ = "Logic-gate"
__license__ = "GPL"
__version__ = "1."
__maintainer__ = "Logic-gate"
__email__ = "amer(@)ma.tc"
__status__ = "Production"


from hashlib import sha512
import time
import tarfile
import random
from numpy import convolve
import requests
import json
import os
import scipy
from random import randint
from xor import Xor
import argparse

abjd = {"7": 1, "3": 2, "5": 3, "6": 4, "9": 5, "1": 6, "2": 7, "4": 8, "8": 9, 
        "0": 0, "K": 20, "L": 30, "M": 40, "N": 50, "S": 60, 'a': 70, "F": 80, "s": 90,
        "Q": 100, "R": 200, "SH":300, "t": 400, "TH": 500, "KH": 600, "DH": 700, "d": 800, "z": 900, 'GH': 1000}

class tidy():

	def keybasePublicKey(self, fingerprint):
		# Remove public key
		base_url = "https://keybase.io/_/api/1.0/user/lookup.json"
		params = dict()
		params['key_fingerprint'] = fingerprint

		r = requests.get(base_url, params=params)

		return self.processR(r)

	def processR(self, r) -> dict:
		if r.status_code == 200:
			basics = json.loads(r.text)['them'][0]['basics']
			primary = json.loads(r.text)['them'][0]['public_keys']['primary']

			username = basics['username']
			public_key = primary['bundle']

			return {'username': username, 'public_key': public_key}

	def hata(self, file):
		with open(file, "rb") as f:
			bytes = f.read()  # read entire file as bytes
			hata = sha512(bytes).hexdigest();
		return hata

	def pair(self, data):
		return ''.join(format(x, 'b') for x in bytearray(data, 'utf-8'))

	def timeStamp(self, dat, fingerprint, l, n, key) -> dict:
		'''
		dat: encrypted data - file
		fingerprint: keybase fingerprint
		l: linking seg_id --> prev grid element
		n: gen seed

		'''
		#keybase = self.keybasePublicKey(fingerprint)
		#username = keybase['username']
		#public_key = keybase['public_key']

		seg_id = self.calPrime(n)
		hata = self.hata(dat)
		ts = str(time.time())
		pair = self.pair(hata) + self.pair(ts) + self.pair(fingerprint)
		# pair = ''.join(format(x, 'b') for x in bytearray(hata, 'utf-8')) + ''.join(format(x, 'b') for x in bytearray(ts, 'utf-8')) + ''.join(format(x, 'b') for x in bytearray(fingerprint, 'utf-8'))
		usersalt = sha512(pair.encode()).hexdigest()
		d = dict()
		d.update({'seg_id': seg_id,
					'master_hash': '',
					'seg': {
					# 'keybase': {
					# 	'fingerprint': fingerprint,
					# 	'username': username,
					# 	'public_key': public_key
					# 	},
                    'key': key,
                    'next_formula': 'NEXT_FORMULA',
					'sig':
						{'hata': hata,
						'ts': ts,
						'l': l,
						'usersalt': usersalt}}
						})
		return d

	def calPrime(self, n) -> int:
		return random.randrange(2**(n-1)+1, 2**n-1)


	def hashTimeStamp(self, dict) -> dict:
		for i in dict['seg']['sig']:
			master_hash = sha512()
			master_hash.update(dict['seg']['sig'][i].encode())
			dict['master_hash'] = master_hash.hexdigest()

	def prepareEncryptedList(self, data_list_in_bytes, n, k) -> list:
		encrypted = []
		data = data_list_in_bytes
		for i in data:
			#encrypted.append(self.mod_op(i, n, k))
			encrypted.append(self.baseOBF(self.mod_op(i,n,k)))
		return encrypted

	def pushTimeStamp(self, dict, n) -> dict:
		if dict['master_hash']:
			data_list_in_bytes = self.data_list(str(dict['seg']))
			#print(data_list_in_bytes)
			#key = self.convolve_key(data_list_in_bytes)
			#print(key)
            
			#convolve = self.convolve(data_list_in_bytes, key)
			#print(convolve)
			encrypted = self.prepareEncryptedList(data_list_in_bytes, n, dict['seg_id'])
			toPush = {'seg_id': dict['seg_id'], 'encrypted_seg': encrypted}
		else:
			toPush = None
		return toPush

	def divide(self, encryptedDoc, chunkSize, division_name, entropy, chunks):
		'''Divide the encrypted file into chunkSize files
		division_name: the name of the chunks (string)

		Future versions will include encrypting the divided files
		'''
		# Thanks to Bidur Devkota
		# http://bdurblg.blogspot.com/2011/06/python-split-any-file-binary-to.html
		# Based on http://penbang.sysbase.org/other_projects/simple_xor.pdf slide 8
		os.makedirs(chunks)
		f = open(encryptedDoc, 'rb')
		data = f.read()
		f.close()
		bytes = len(data)
		noOfChunks= bytes/chunkSize
		if(bytes%chunkSize):
			noOfChunks+=1
		f = open('info.txt', 'w')
		f.write(encryptedDoc+','+division_name+','+str(noOfChunks)+','+str(chunkSize))
		f.close()
		chunkNames = []
		for i in range(0, bytes+1, chunkSize):
			fn1 = "%s_%s" %(division_name, i)
			# chunkKey = "key%s" %i
			# encryptedChunk = 'Encrypted%s' %i
			chunkNames.append(fn1)
			f = open(fn1, 'wb')
			f.write(data[i:i+ chunkSize])
			f.close()


	def encrypt(self, doc,
				entropy,
				n,
				chunkSize,
				):
		'''[doc (+) key_out(entropy)] + RubbishOutput(n) = encryptedDoc
		 encryptedDoc / chunkSize = division_name(chunkSize)
		 tar[division_name(chunkSize)] (+) tarkey = tarName
		'''

		xor = Xor()
		docSplit = doc.split('.')[0]
		encryptedDoc = f'{docSplit}.tidy' 
		key_out = f'{docSplit}.tkey'
		RubbishOutput = f'{docSplit}.trubbish'
		chunks_folder = f'{docSplit}_chunks'
		division_name = f'{chunks_folder}/{docSplit}_chuck_'
		tarIN = f'{docSplit}.tar'
		
		tarName = f'{docSplit}.tidy.tar'
		tarkey = f'{docSplit}.tkey.tar'
		xor.encrypt(doc, encryptedDoc, key_out, entropy)
		xor.rubbish(encryptedDoc, RubbishOutput, n)
		self.divide(encryptedDoc, chunkSize, division_name, entropy, chunks_folder)

		tar = tarfile.open(tarIN, 'w:tar')
		tar.add(chunks_folder, filter=xor.tarinfo)
		tar.close()

		xor.encrypt(tarIN, tarName, tarkey, entropy)


	def data_list(self, data_in_bytes):
		l = []
		for i in bytes(data_in_bytes, 'utf-8'):
			l.append(i)
		return l

	def mod_op(self, e, n, k):
		return (n * e) % k

	def remod_op(self, enc, n, k):
		return enc / n % k
	
	def baseOBF(self, n):
		KEY_LIST = list(abjd.keys())
		VALUE_LIST = list(abjd.values())
		j = []
		for i in str(n):
			j.append(KEY_LIST[VALUE_LIST.index(int(i))])

		return "".join(j)
   # def convolve_key(self, data_list):
	# 	l = []
	# 	for i in range(len(data_list)):
	# 		l.append(randint(1000, 9999))
	# 	return l

	# def convolve(self, data_list_in_bytes, key_list):
	# 	'''
	# 	Dont use fftconvolve, it will not create an adequte convolution
	# 	based on testing

	# 	'''
	#     f = scipy.signal.convolve(data_list_in_bytes, key_list)
	#     return f

	# def deconvlve(self, key_list, agreement):
	# 	a = scipy.signal.deconvolve(key_list, agreement)
	# 	return a

	# def print_seg(self, deconvolve):
	# 	'''
	# 	deconvolve is [0]
	# 	'''
	# 	new_list = []
	# 	for i in deconvolve:
	# 		new_list.append(int())
	# 	return "".join(map(chr, list(map(int, deconvolve))))


    # def test(ran, arr):
    #     print(arr)
    #     for i in tqdm(range(1, ran)):
    #         for ii n range(1, ran):
    #             for iii in range(1, ran):
    #                 r, re = scipy.signal.deconvolve(arr, [i,ii, iii])
    #                 print(i, ii, iii)

    #                 if all(e==0 for e in re):
    #                     if all((ee).is_integer() for ee in r):
    #                         print(i,ii,iii, r, re)
    #                         print("".join(map(chr, list(map(int,r)))))


