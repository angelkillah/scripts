import os
import shutil
from modules import *

IS_UNKNOWN = 0
IS_ZIP     = 1
IS_PE      = 2

class Core(object):

    def __init__(self):
        self.db = 0
        self.archive = 0

    def wrap_dump_db(self):
        self.db = DB.new()
        if self.db.create() == 0:
            print "[-] Cannot create/access database"
            return 0
        return self.db.dump()


    def wrap_get_all_unique_tags(self):
        self.db = DB.new()
        if self.db.create() == 0:
            print "[-] Cannot create/access database"
            return 0
        return self.db.get_all_unique_tags()

    def check_similarities(self, filepath):
        self.db = DB.new()
        if self.db.create() == 0:
            return "[-] Cannot create/access database"       
        if filepath:
            self.archive = File.new()
            filetype = self.archive.is_valid(filepath)
            res = []
            out = []
            if filetype == IS_ZIP:   
                for root, dirs, files in os.walk(filepath + ".dir"):
                    for f in files:
                        hash_file = self.archive.get_file_hash(root + "/" + f)
                        hash_rich = self.archive.get_rich_hash(root + "/" + f)
                        if hash_file and hash_rich:
                            res, len_res = self.db.get_similar_rich(hash_file, hash_rich)
                        if res:
                            out.append([hash_file] + [len_res] + res)
                return out
            elif filetype == IS_PE:
                hash_file = self.archive.get_file_hash(filepath)
                hash_rich = self.archive.get_rich_hash(filepath)
                if hash_file and hash_rich:
                    res, len_res = self.db.get_similar_rich(hash_file, hash_rich)
                    if res:
                        out.append([hash_file] + [len_res] + res)
                return out
            else:
                return "[-] Error : unknown filetype"

    def wrap_store_to_db(self, filepath, tag):
        self.db = DB.new()
        if self.db.create() == 0:
            return "[-] Cannot create/access database"        
        if filepath and tag:
            self.archive = File.new()
            filetype = self.archive.is_valid(filepath)
            new_entries = 0
            if filetype == IS_ZIP:
                print "ZIP file detected"   
                for root, dirs, files in os.walk(filepath + ".dir"):
                    for f in files:
                        if self.archive.store_to_db(self.db, root + "/" + f, tag):
                          new_entries +=1
            elif filetype == IS_PE:
                print "PE file detected"
                new_entries += self.archive.store_to_db(self.db, filepath, tag)
            else:
                return "[-] Error : unknown filetype"
            
            if new_entries > 0:
                return "[+] %d entries added to DB" % (new_entries)
            else:
                return "[-] archive's metadata already exist in the DB"

            