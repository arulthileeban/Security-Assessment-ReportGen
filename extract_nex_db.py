import sqlite3
from xml.etree import ElementTree as ET
from collections import defaultdict
#Function to assign Risk Rating
def ass_rr(score):
    if score>0 and score<5:
        return "Low"
    elif score>=5 and score<8:
        return "Medium"
    elif score>=8:
        return "High"

def extract_nexpose(n,ftitle):
    contents=[]
    conn=sqlite3.connect(ftitle+'.db')
    #Constructing a tree around the xml object using ET
    trees=[]
    for i in range(1,n+1):
        with open('uploads/nexpose'+str(i)+'.xml', 'rt') as f:
            trees.append(ET.parse(f))

    dname=defaultdict(list)
    ids=[]

    #Extract title and ip and compare create a dictionary with title as key
    for tree in trees:
        for node in tree.findall('.//nodes/node'):
            ip=node.attrib.get('address')
            for i in node.findall('.//tests/test'):
                vid=i.attrib.get('id')
                ids.append((vid,ip))

    #Construction of dictionary from the ip and title
    for k,v in ids:
        dname[k].append(v)

    #Extraction of data from the tree
    for tree in trees:
        for node in tree.findall('.//VulnerabilityDefinitions/vulnerability'):

            #Name extraction
            name=node.attrib.get('title')
            id=node.attrib.get('id')



            #Severity extraction
            severity=node.attrib.get('severity')
            risk_rat=ass_rr(int(severity))

            #Description extraction
            for i in node.findall('.//description/ContainerBlockElement/Paragraph'):
                desc =i.text

            #Solution extraction from multiple children nodes
            sol1=""
            sol2=""
            sol3=""
            for i in node.findall('.//solution/ContainerBlockElement/Paragraph'):
                sol1+=i.text
                for j in i.findall('.//URLLink'):
                    sol2+=j.attrib.get('LinkURL')
                for j in i.findall('.//Paragraph'):
                    sol3+=j.text

            #Remove all extra spaces from the solution and add them together
            sol1=sol1.replace("          "," ")
            sol2=sol2.replace("          "," ")
            sol3=sol3.replace("          "," ")
            sol1=sol1.replace("\t"," ")
            sol2=sol2.replace("\t","")
            sol3=sol3.replace("\t","")

            sol=sol1.replace("\n","")+"\n"+sol2.replace("\n","")+"\n"+sol3.replace("\n","")+"\n"

            #Retrieving CVE for that particular vulnerability
            for j in node.findall('.//reference'):
                if j.attrib.get('source')=="CVE" and j.text!='':
                    cve= j.text

            #Append all details into contents array
            contents.append([name,desc,id,risk_rat,sol,'',cve])
        for i in contents:
            for j in dname[id]:
                conn.execute("INSERT INTO Info(`Title`,`Description`,`IP`,`Risk Rating`,`Solution`,`See also`,`CVE`) VALUES(?,?,?,?,?,?,?);",(i[0],i[1],j,i[3],i[4],i[5],i[6]))
        conn.commit()
    conn.close()

