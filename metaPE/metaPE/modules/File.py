import pefile
import zipfile
import os
import hashlib

IS_UNKNOWN  =  0
IS_ZIP      =  1
IS_PE       =  2

class File(object):

    def __init__(self):
        self.filepath = None

    def is_valid(self, filepath):
        self.filepath = filepath
        """ PE or zip archive """
        if zipfile.is_zipfile(filepath):
            if not(os.path.exists(filepath + ".dir")):
                os.makedirs(filepath + ".dir")
                zipf = zipfile.ZipFile(filepath, 'r')
                zipf.extractall(filepath + ".dir")
                zipf.close()
            return IS_ZIP
        else:   
            try:
                pe = pefile.PE(os.path.realpath(self.filepath))
            except Exception as e:
                return IS_UNKNOWN
        return IS_PE

    def get_file_hash(self, filepath):
        with open(filepath, 'rb') as f_file:
            f_data = f_file.read()
            h_data = hashlib.sha1(f_data).hexdigest()
            return h_data

    def get_rich_hash(self, filepath):
        try:
            pe = pefile.PE(os.path.realpath(filepath))
        except Exception as e:
            return 0

        hash_rich = 0

        if pe.RICH_HEADER:
            data = pe.RICH_HEADER.clear_data
            hash_rich = hashlib.sha1(pe.RICH_HEADER.clear_data).hexdigest()

        return hash_rich

    def store_to_db(self, inst_db, filepath, tag):
        hash_rich = self.get_rich_hash(filepath)
        """ store file metadata to DB """
        if hash_rich and tag:
            hash_file = self.get_file_hash(filepath)
            return inst_db.add_metadata(tag, hash_file, hash_rich)
        return hash_rich

def new():
    return File()
