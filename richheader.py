#!/usr/bin/env python2
#-*- coding: utf-8 -*-

import argparse
import sys
import os
import pefile
import hashlib
import sqlite3
import collections

hashes = []

def get_hash(f):
    with open(f, 'rb') as f_file:
        f_data = f_file.read()
        h_data = hashlib.sha1(f_data).hexdigest()
        return h_data
            
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

def parse_file(f, cur, store=False, scan=False):
    global hashes
    try:
        pe = pefile.PE(os.path.realpath(f))
    except Exception as e:
        return 0    
   
    h_rich = 0
    if pe.RICH_HEADER:
        data = pe.RICH_HEADER.clear_data
        h_rich = hashlib.sha1(pe.RICH_HEADER.clear_data).hexdigest()
        if not(scan) and not(store):
            print "%s:%s" % (f, h_rich)
        hashes.append(h_rich)
        
        if store:
            h_data = get_hash(f)
            cur.execute("SELECT id_file FROM File WHERE hash_file='"+h_data+"'")
            if cur.fetchone() == None:
                cur.execute("INSERT INTO File(path_file, hash_file, hash_rich) VALUES(?,?,?)", (f, h_data, h_rich))
                return 1
            return 0

    return h_rich
       
def parse_folder(folder, cur, store):
    new_entries = 0
    for root, dirs, files in os.walk(folder):
        for f in files:
            if parse_file(root + "/" + f, cur, store, 0):
                new_entries +=1
    return new_entries

def main(argc, argv):
    global hashes
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("-d", "--directory", help="Specify a directory containing the samples")
    parser.add_argument("-f", "--file", help="Specify a file or a list of files", required=False, nargs="+")
    parser.add_argument("-s", "--store", help="Store rich info in database", required=False, action="store_true")

    try:
        args = parser.parse_args()
    except IOError as e:
        parser.error(e)
        return 0

    if len(sys.argv) == 1:
        parser.print_help()
        return 0 

    # init DB
    try:
        conn = sqlite3.connect("richbase.db")
        cur = conn.cursor()
        cur.execute("CREATE TABLE IF NOT EXISTS File(id_file INTEGER PRIMARY KEY, path_file TEXT, hash_file TEXT, hash_rich TEXT)")
        conn.commit()
    except sqlite3.Error, e:
        if conn:
            conn.rollback()
            print "Error %s:" % e.args[0]
            return 0

    if args.file:
        files = args.file
        for f in files:
            if os.path.exists(f):
                h_rich = parse_file(f, cur, 0, args.file)
                if h_rich != 0:
                    cur.execute("SELECT path_file, hash_file FROM File WHERE hash_rich='"+h_rich+"'")
                    results = cur.fetchall()
                    if results == None:
                        print "[-] %s has no common known rich header info" % (f)
                        return 0
                    for res in results:
                        if res[1] != get_hash(f):
                            print res

    if args.directory:
        folder = args.directory
        if os.path.exists(folder):
            new_entries = parse_folder(folder, cur, args.store)
            if args.store:
                if new_entries:
                    print "[+] %d entries added to DB" % (new_entries)
            if hashes:
                hashes = [item for item, count in collections.Counter(hashes).items() if count > 1]
                if not(args.store):
                    generate_yara(hashes)
            else:
                print "[-] No common rich header info :("
            
    if conn:
        conn.commit()
        cur.close()
        conn.close()

if __name__ == "__main__":
    main(len(sys.argv), sys.argv)
