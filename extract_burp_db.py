import sqlite3
from xml.etree import ElementTree as ET
from HTMLParser import HTMLParser

class MLStripper(HTMLParser):
    def __init__(self):
        self.reset()
        self.fed = []
    def handle_data(self, d):
        self.fed.append(d)
    def get_data(self):
        return ''.join(self.fed)

def strip_tags(html):
    s = MLStripper()
    s.feed(html)
    return s.get_data()

def extract_burp(n,ftitle):

    conn=sqlite3.connect(ftitle+'.db')
    #Constructing a tree around the xml object using ET
    trees=[]
    for i in range(1,n+1):
        with open('uploads/burp'+str(i)+'.xml', 'rt') as f:
            trees.append(ET.parse(f))
    content=[]
    for tree in trees:
        for node in tree.findall('.//issue'):
            name=node.find('name').text
            ip=node.find('host').attrib.get('ip')
            soln=''
            severity=node.find('severity').text
            desc=node.find('issueBackground').text
            desc=strip_tags(desc)
#119.9.70.190
            if node.find('remediationBackground') is not None :
                soln=node.find('remediationBackground').text
            soln=strip_tags(soln)
            if severity=='High' or severity=='Medium' or severity=='Low':
                content.append([name,desc,ip,severity,soln,'',''])
    for i in content:
        conn.execute("INSERT INTO Info(`Title`,`Description`,`IP`,`Risk Rating`,`Solution`,`See also`,`CVE`) VALUES(?,?,?,?,?,?,?);",(i[0],i[1],i[2],i[3],i[4],i[5],i[6]))
    conn.commit()
    conn.close()

