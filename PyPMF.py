''' 
   A simple python library to manage SysInternals Process Monitor 
   filter files. 

'''
import struct

class PMF(object):
    autocommit = False
    columns = [(0x00009c98, "Architecture"),
               (0x9c93,'Authentication ID'),
               (0x9c96,'Category'),
               (0x9c82,'ComandLine'),
               (0x9c82,'Company'),
               (0x9c74,'Date & Time'),
               (0x9c81,'Description'),
               (0x9c79,'Detail'),
               (0x9c8d,'Duration'),
               (0x9c92,'Event Class'),
               (0x9c84,'Image Path'),
               (0x9c95,'Integrity'),
               (0x9c77,'Operation'),
               (0x9c97,'Parent PID'),
               (0x9c87,'Path'),
               (0x9c76,'PID'),
               (0x9c75,'Process Name'),
               (0x9c8c,'Relative Time'),
               (0x9c78,'Result'),
               (0x9c7a,'Sequence'),
               (0x9c85,'Session'),
               (0x9c88,'TID'),
               (0x9c8e,'Time Of Day'),
               (0x9c83,'User'),
               (0x9c91,'Version'),
               (0x9c94,'Virtualized'),
               ]
    relations = [ 'is', 'is not', 'less than', 'more than', 'begins with', 'ends with', 'contains', 'excludes' ]
    actions = ["EXCLUDE", "INCLUDE"]
    def unpack(self, fmt):
        assert len(fmt) in [1,2]
        return struct.unpack(fmt,self.f.read(len(struct.pack(fmt,0))))[0]
    def read_byte(self):
        return self.unpack("B")
    def read_int(self):
        return self.unpack("<L")
    def read_string(self):
        size = self.unpack("<L")
        return self.f.read(size)

    def pack(self, fmt, val):
        assert len(fmt) in [1,2]
        self.f.write(struct.pack(fmt,val))
    def write_byte(self,val):
        return self.pack("B",val)
    def write_int(self,val):
        return self.pack("<L",val)
    def write_string(self,val):
        val = unicode(val).encode("utf-16")[2:]
        self.pack("<L", len(val))
        return self.f.write(val)

    def __init__(self, filename):
        self.rules = []
        try:
            self.f = file(filename,'r+')
            self.read_int() #size in bytes
            self.read_byte() #version ?
            n=self.read_int()
            for i in range(0,n):
                col = self.read_int()
                rel = self.read_int()
                action = self.read_byte()
                value = self.read_string()
                self.f.read(8)
                self.rules.append((i,col,rel,action,value))
        except Exception,e:
            print "Could not read file.",e
            self.f = file(filename,'w+b')
        self.f.seek(0)

    def __str__(self):
        ret  = "ID    Column                  Relation        Value           Action          \n"
        for rule_id, col,rel,action,value in self.rules:
            ret += str(rule_id).ljust(6,' ')
            ret += ("%s"%dict(PMF.columns).setdefault(col, "%04x"%col )).ljust(24,' ')
            ret += ("%s"%PMF.relations[rel]).ljust(16,' ')
            ret += (value.replace('\x00','')).ljust(16,' ')
            ret += (PMF.actions[action]).ljust(16,' ')
            ret += "\n"
        return ret

    def append(self, col,rel,value,action):
        assert col in [x[1] for x in PMF.columns]
        assert rel in PMF.relations
        assert action in PMF.actions
        assert type(value) in [str, unicode]

        rule_id = max([0] + [ x[0] for x in self.rules])+1 
        self.rules.append(( rule_id,
                      [x[0] for x in PMF.columns if x[1]==col][0],
                      PMF.relations.index(rel),
                      PMF.actions.index(action),
                      unicode(value+'\x00')))

        #check for duplicates and rollback
        if len(set([x[1:] for x in self.rules])) != len(self.rules):
            self.remove(rule_id)
            raise Exception("Duplicated Rule")

        return rule_id

    def remove(self, rule_id):
        self.rules = [x for x in self.rules if x[0] != rule_id]

    def clear(self):
        self.rules = []


    def lst(self):
        ret = []
        for rule_id, col,rel,action,value in self.rules:
            ret.append( (rule_id,
                         dict(PMF.columns)[col],
                         PMF.relations[rel],
                         unicode(value),
                         PMF.actions[action] ))
        return ret

    def commit(self,offset=0):
        self.f.seek(offset+4)

        self.write_byte(1) #version ?
        self.write_int(len(self.rules))
        for rule_id, col,rel,action,value in self.rules:
            self.write_int(col)
            self.write_int(rel)
            self.write_byte(action)
            self.write_string(unicode(value))
            self.f.write("\x00"*8)
        size = self.f.tell()-offset-4
        self.f.seek(offset)
        self.write_int(size)
        self.f.seek(size+offset+4)
        self.f.truncate()

    def __del__(self):
        try:
            if PMF.autocommit:
                self.commit()
        except:
            pass

if __name__ == '__main__':
    import sys
    pmf = PMF(sys.argv[1])
    print pmf
    #for x in pmf.lst():
    #    pmf.remove(x[0])
    #pmf.append("Operation","is", "RegQueryValue", "INCLUDE")
    #pmf.append("Operation","is", "CreateFile", "INCLUDE")
    #print pmf
    #pmf.commit()

