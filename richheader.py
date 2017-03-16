#!/usr/bin/env python2

import argparse
import sys
import os
import pefile
import hashlib
import collections

hashes = []

def generate_yara(hashes):
    rule = ""
    if hashes:
        rule += "import \"pe\"\r\nimport \"hash\"\r\n\r\n"
        rule += "rule Common_RichSignature{\r\n" + "  condition:\r\n\t"
        for i in range(len(hashes)-1):
            rule += "hash.sha1(pe.rich_signature.clear_data) == \"" + hashes[i] + "\" or " 
        rule += "hash.sha1(pe.rich_signature.clear_data) == \"" + hashes[i+1] + "\" \r\n}"  
        with open("rich.yar", "w+") as f:
            f.write(rule)
            print "[+] rich.yar ready... enjoy !" 

def parse_file(f):
    global hashes
    try:
        pe = pefile.PE(os.path.realpath(f))
    except Exception as e:
        return 0    
   
    if pe.RICH_HEADER:
        data = pe.RICH_HEADER.clear_data
        h = hashlib.sha1(pe.RICH_HEADER.clear_data).hexdigest()    
#        print "file : %s clear_data : %s" % (f, h)
        hashes.append(h)  

def parse_folder(folder):
    for root, dirs, files in os.walk(folder):
        for f in files:
            parse_file(root + "/" + f)

def main(argc, argv):
    global hashes
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("-d", "--directory", help="Specify a directory containing the samples")
    parser.add_argument("-f", "--file", help="Specify a file or a list of files", required=False, nargs="+")

    try:
        args = parser.parse_args()
    except IOError as e:
        parser.error(e)
        return 0

    if len(sys.argv) == 1:
        parser.print_help()
        return 0 

    if args.file:
        files = args.file
        for f in files:
            if os.path.exists(f):
                parse_file(f)
        if hashes:
            hashes = [item for item, count in collections.Counter(hashes).items() if count > 1]
            generate_yara(hashes)
        else:
            print "[-] No common rich header info :("

    if args.directory:
        folder = args.directory
        if os.path.exists(folder):
            parse_folder(folder)
            if hashes:
                hashes = [item for item, count in collections.Counter(hashes).items() if count > 1]
                generate_yara(hashes)
            else:
                print "[-] No common rich header info :("

if __name__ == "__main__":
    main(len(sys.argv), sys.argv)
