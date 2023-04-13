# Tidy-Testing Branch
This branch is used for testing. The supplied code is not intended for production purposes. Currently limited to encrypting files.

This branch will be under heavy development. 

Basic usage:
 
```
positional arguments:
  file_to_encrypt  Path to the file to be encrypted
  entropy          Shannon entropy value for the encryption key
  rubbish_length   Length of the randomly generated key prefix
  chunk_size       Size of chunks to read from the input file
  fingerprint      Fingerprint to use for the output file
  seed             Seed to use for the random number generator

options:
  -h, --help       show this help message and exit
```

```
python3 main.py file 0.1 3 1000 H113H 1024
```

Requirements are not supplied in repo:

```
chardet==5.1.0
numpy==1.22.4
requests==2.28.1
scipy==1.10.1
tqdm==4.64.1
```

 