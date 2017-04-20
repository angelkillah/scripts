import sqlite3

class DB(object):

    def __init__(self):
        self.conn = 0
        self.cur = 0

    def get_similar_rich(self, hash_file, hash_rich):
        if self.conn == 0 or self.cur == 0:
            self.create()
        self.cur.execute("SELECT tag, hash_file FROM File WHERE hash_rich='"+hash_rich+"' and hash_file!='"+hash_file+"'")
        results = self.cur.fetchall()
        if results == None:
            return 0
        else:
            return results, len(results)

    def dump(self):
        if self.conn == 0 or self.cur == 0:
            self.create()
        self.cur.execute("SELECT * From File")
        results = self.cur.fetchall()
        if results == None:
            return 0
        else:
            return results
        
    def get_all_unique_tags(self):
        if self.conn == 0 or self.cur == 0:
            self.create()
        self.cur.execute("SELECT DISTINCT tag From File")
        results = self.cur.fetchall()
        if results == None:
            return 0
        else:
            return results


    def create(self):
        try:
            self.conn = sqlite3.connect("richbase.db")
            self.cur = self.conn.cursor()
            self.cur.execute("CREATE TABLE IF NOT EXISTS File(id_file INTEGER PRIMARY KEY, tag TEXT, hash_file TEXT, hash_rich TEXT)")
            self.conn.commit()
        except sqlite3.Error, e:
            if self.conn:
                self.conn.rollback()
                print "Error %s:" % e.args[0]
                return 0
        return 1

    def add_metadata(self, tag, hash_file, hash_rich):
        if self.conn == 0 or self.cur == 0:
            self.create()
        self.cur.execute("SELECT id_file FROM File WHERE hash_file='"+hash_file+"'")
        if self.cur.fetchone() == None:
            self.cur.execute("INSERT INTO File(tag, hash_file, hash_rich) VALUES(?,?,?)", (tag, hash_file, hash_rich))
            self.conn.commit()
            return 1
        return 0

def new():
    return DB()