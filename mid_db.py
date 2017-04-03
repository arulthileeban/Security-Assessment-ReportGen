import sqlite3,extract_csv_db,extract_nex_db,extract_acu_db,extract_burp_db
from collections import defaultdict

def db_creation(n1,n2,n3,n4,ftitle):
    p=open(ftitle+'.db','wb')
    p.close()

    conn=sqlite3.connect(ftitle+'.db')
    conn.execute('CREATE TABLE `Info` ('
                 '  `Id` INTEGER primary key autoincrement,'
                 '	`Title`	TEXT,'
                 '	`Description`	TEXT,'
                 '	`IP`	TEXT,'
                 '	`Risk Rating`	TEXT,'
                 '`Solution`	TEXT,'
                 '	`See also`	TEXT,'
                 '	`CVE`	TEXT)')

    conn.execute("DELETE FROM Info;")
    conn.commit
    conn.close()
    if n1>0:
        extract_csv_db.read_csv(n1,ftitle)
    if n2>0:
        extract_nex_db.extract_nexpose(n2,ftitle)
    if n3>0:
        extract_acu_db.extract_acu(n3,ftitle)
    if n4>0:
        extract_burp_db.extract_burp(n4,ftitle)
def content_creation(ftitle):
    dname=defaultdict(list)
    ids=[]
    conn=sqlite3.connect(ftitle+'.db')
    cur=conn.execute('select title,ip from info')
    for i in cur:
        ids.append((i[0],i[1]))

    #Construction of dictionary from the ip and title
    for k,v in ids:
        dname[k].append(v)

    cont=conn.execute('select * from info')
    names=[]
    cves=[]
    content_cve=[]
    content_ncve=[]
    for i in cont:
        arr=[]
        for j in i:
            t=0
            if t==0:
                t+=1
                continue
            arr.append(str(j))

        if i[0] in names:
            continue
        else:
            names.append(arr[0])
        if arr[-1] in cves and arr[-1]!='':
            continue
        else:
            cves.append(arr[-1])
        st=""
        for j in dname[arr[0]]:
            st+="|"+j
        arr[2]=st
        arr.insert(2,"Network Vulnerability Assessment and Penetration Testing")
        if arr[-1]=='':
            content_ncve.append(arr)
        else:
            content_cve.append(arr)
    return content_cve,content_ncve
