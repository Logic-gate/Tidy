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
from .xor import Xor
import argparse
from numba import jit

abjd = {"7": 1, "3": 2, "5": 3, "6": 4, "9": 5, "1": 6, "2": 7, "4": 8, "8": 9, 
        "0": 0, "K": 20, "L": 30, "M": 40, "N": 50, "S": 60, 'a': 70, "F": 80, "s": 90,
        "Q": 100, "R": 200, "SH":300, "t": 400, "TH": 500, "KH": 600, "DH": 700, "d": 800, "z": 900, 'GH': 1000}


class Tidy():
    def keybase_public_key(self, fingerprint: str) -> dict:
        """
        Remove public key.
        """
        base_url = "https://keybase.io/_/api/1.0/user/lookup.json"
        params = {'key_fingerprint': fingerprint}
        r = requests.get(base_url, params=params)
        return self.process_r(r)
        
    def process_r(self, r) -> dict:
        """
        Process request response.
        """
        if r.status_code == 200:
            basics = json.loads(r.text)['them'][0]['basics']
            primary = json.loads(r.text)['them'][0]['public_keys']['primary']
            username = basics['username']
            public_key = primary['bundle']
            return {'username': username, 'public_key': public_key}

    def hata(self, file: str) -> str:
        """
        Hash a file using sha512 algorithm.
        """
        with open(file, "rb") as f:
            bytes = f.read()
            hata = sha512(bytes).hexdigest()
        return hata
    
    def pair(self, data: str) -> str:
        return ''.join(format(x, 'b') for x in bytearray(data, 'utf-8'))

    def timeStamp(self, dat: bytes, fingerprint: str, l: str, n: int, key: str) -> dict:
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
                        #   'fingerprint': fingerprint,
                        #   'username': username,
                        #   'public_key': public_key
                        #   },
                        'key': key,
                        'next_formula': 'NEXT_FORMULA',
                        'sig': {
                            'hata': hata,
                            'ts': ts,
                            'l': l,
                            'usersalt': usersalt
                        }
                    }
                })
        return d

    def calPrime(self, n: int) -> int:
        return random.randrange(2**(n-1)+1, 2**n-1)

    def hash_time_stamp(self, dictionary: dict) -> dict:
        for i in dictionary['seg']['sig']:
            master_hash = sha512()
            master_hash.update(dictionary['seg']['sig'][i].encode())
            dictionary['master_hash'] = master_hash.hexdigest()
        #return dictionary


    def prepare_encrypted_list(self, data_list_in_bytes: list, n: int, k: int) -> list:
        encrypted = []
        data = data_list_in_bytes
        for i in data:
            # encrypted.append(self.mod_op(i, n, k))
            encrypted.append(self.baseOBF(self.mod_op(i, n, k)))
        return encrypted


    def push_time_stamp(self, dictionary: dict, n: int) -> dict:
        if dictionary['master_hash']:
            data_list_in_bytes = self.data_list(str(dictionary['seg']))
            # print(data_list_in_bytes)
            # key = self.convolve_key(data_list_in_bytes)
            # print(key)

            # convolve = self.convolve(data_list_in_bytes, key)
            # print(convolve)
            encrypted = self.prepare_encrypted_list(data_list_in_bytes, n, dictionary['seg_id'])
            to_push = {'seg_id': dictionary['seg_id'], 'encrypted_seg': encrypted}
        else:
            to_push = None
        return to_push

    def divide(self, encryptedDoc: str, chunkSize: int, division_name: str,
               entropy: str, chunks: str) -> None:
        """
        Divide the encrypted file into chunkSize files
        division_name: the name of the chunks (string)

        Future versions will include encrypting the divided files
        """
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

    def encrypt(self, doc: str, entropy: str, n: int, chunkSize: int) -> None:
        """[doc (+) key_out(entropy)] + RubbishOutput(n) = encryptedDoc
         encryptedDoc / chunkSize = division_name(chunkSize)
         tar[division_name(chunkSize)] (+) tarkey = tarName
        """
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

    def data_list(self, data_in_bytes: bytes) -> list:
        l = []
        for i in bytes(data_in_bytes, 'utf-8'):
            l.append(i)
        return l

    def mod_op(self, e: int, n: int, k: int) -> int:
        return (n * e) % k

    # def mod_op(self, e, n, k):
    #     return (n * e) % k

    def remod_op(self, enc: int, n: int, k: int) -> int:
        return enc / n % k

    def baseOBF(self, n: int) -> str:
        KEY_LIST = list(abjd.keys())
        VALUE_LIST = list(abjd.values())
        j = []
        for i in str(n):
            j.append(KEY_LIST[VALUE_LIST.index(int(i))])

        return "".join(j)