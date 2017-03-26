import csv,sqlite3

def read_csv(n,ftitle):
    conn=sqlite3.connect(ftitle+'.db')

    content=[]
    for i in range(1,n+1):
        ifile  = open('uploads/nessus'+str(i)+'.csv', "rb")
        if not ifile:break
        reader=csv.reader(ifile)
        rno=0
        for row in reader:
            if row[3]!="None" and rno!=0:
                arr=[]
                name=row[7]
                cve=row[1]
                desc=row[9]
                ip=row[4]+":"+row[6]
                rr=row[3]
                sol=row[10]+"\n"
                see_m=row[11]
                content.append([name,desc,ip,rr,sol,see_m,cve])
            rno += 1
        for i in content:
            conn.execute("INSERT INTO Info(`Title`,`Description`,`IP`,`Risk Rating`,`Solution`,`See also`,`CVE`) VALUES(?,?,?,?,?,?,?);",(i[0],i[1],i[2],i[3],i[4],i[5],i[6]))
        conn.commit()
    conn.close()

