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

def extract_acu(n,ftitle):
    conn=sqlite3.connect(ftitle+'.db')
    trees=[]
    for i in range(1,n+1):
        with open('uploads/acunetix'+str(i)+'.xml', 'rt') as f:
            trees.append(ET.parse(f))
    contents=[]
    for tree in trees:
        for node in tree.findall('.//Scan'):
            iparr=node.find('Crawler').attrib.get('StartUrl')
            iparr=iparr.split('/')
            ip=iparr[2]
            for rep in node.findall('.//ReportItems/ReportItem'):
                title=rep.find('Name').text
                desc=rep.find('Description').text
                desc=strip_tags(desc)
                soln=rep.find('Recommendation').text
                soln=strip_tags(soln)
                rr=rep.find('Severity').text
                if rr!='info':
                    rr = rr[:1].upper() + rr[1:]
                    contents.append([title,desc,ip,rr,soln,'',''])

    for i in contents:
        conn.execute("INSERT INTO Info(`Title`,`Description`,`IP`,`Risk Rating`,`Solution`,`See also`,`CVE`) VALUES(?,?,?,?,?,?,?);",(i[0],i[1],i[2],i[3],i[4],i[5],i[6]))
    conn.commit()
    conn.close()

