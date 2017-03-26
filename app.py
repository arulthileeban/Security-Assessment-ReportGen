import os,sqlite3
# We'll render HTML templates and access data sent by POST
# using the request object from flask. Redirect and url_for
# will be used to redirect the user once the upload is done
# and send_from_directory will help us to send/show on the
# browser the file that the user just uploaded
from flask import Flask, render_template, request, redirect, url_for, send_from_directory
from werkzeug import secure_filename
import write_doc,mid_db
# Initialize the Flask application
app = Flask(__name__)

# This is the path to the upload directory
app.config['UPLOAD_FOLDER'] = 'uploads/'
# These are the extension that we are accepting to be uploaded
app.config['ALLOWED_EXTENSIONS'] = set(['xml', 'csv'])

n1=0
n2=0
n3=0
n4=0

# For a given file, return whether it's an allowed type or not
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in app.config['ALLOWED_EXTENSIONS']

# This route will show a form to perform an AJAX request
# jQuery is loaded to execute the request and update the
# value of the operation
@app.route('/')
def index():
    return render_template('index.html')

name = ""
# Route that will process the file upload
@app.route('/upload', methods=['POST'])
def upload():
    # Get the name of the uploaded file
    file1l = request.files.getlist('nesfile')
    file2l = request.files.getlist('nexfile')
    file3l = request.files.getlist('acufile')
    file4l = request.files.getlist('burfile')
    global name
    name=request.form['text']
    n1=len(file1l)
    n2=len(file2l)
    n3=len(file3l)
    n4=len(file4l)
    if str(file1l[0]).replace('\'','')=='<FileStorage: u (application/octet-stream)>':
        n1=0
    if str(file2l[0]).replace('\'','')=='<FileStorage: u (application/octet-stream)>':
        n2=0
    if str(file3l[0]).replace('\'','')=='<FileStorage: u (application/octet-stream)>':
        n3=0
    if str(file4l[0]).replace('\'','')=='<FileStorage: u (application/octet-stream)>':
        n4=0
    i=0
    for file1 in file1l:
        i+=1
        if file1 and allowed_file(file1.filename):
            filename = secure_filename(file1.filename)
            file1.save(os.path.join(app.config['UPLOAD_FOLDER'],"nessus"+str(i)+".csv" ))
    i=0
    for file2 in file2l:
        i+=1
        if file2 and allowed_file(file2.filename):
            filename = secure_filename(file2.filename)
            file2.save(os.path.join(app.config['UPLOAD_FOLDER'], "nexpose"+str(i)+".xml"))
    i=0
    for file3 in file3l:
        i+=1
        if file3 and allowed_file(file3.filename):
            filename = secure_filename(file3.filename)
            file3.save(os.path.join(app.config['UPLOAD_FOLDER'], "acunetix"+str(i)+".xml"))
    i=0
    for file4 in file4l:
        i+=1
        if file4 and allowed_file(file4.filename):
            filename = secure_filename(file4.filename)
            file4.save(os.path.join(app.config['UPLOAD_FOLDER'], "burp"+str(i)+".xml"))

    mid_db.db_creation(n1,n2,n3,n4,name)
    db=sqlite3.connect(name+'.db')
    cursor = db.execute('SELECT Id,Title,IP from Info')
    return render_template('list.html', items=cursor.fetchall())

@app.route('/list_delete', methods=['POST'])
def delete():
    id=request.form['id']
    db=sqlite3.connect(name+'.db')
    db.execute('DELETE from Info where ID='+str(id))
    cursor = db.execute('SELECT Id,Title,IP from Info')
    db.commit
    return render_template('list.html', items=cursor.fetchall())
@app.route('/build', methods=['POST'])
def build():
    print 1
    write_doc.write_doc(name)
    return "Record written successfully"

# This route is expecting a parameter containing the name
# of a file. Then it will locate that file on the upload
# directory and show it on the browser, so if the user uploads
# an image, that image is going to be show after the upload
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'],
                               filename)

@app.route('/print_items')
def print_items():
    db=sqlite3.connect(name+'.db')
    cursor = db.execute('SELECT Id,Title from Info')
    return render_template('list.html', items=cursor.fetchall())

if __name__ == '__main__':
    app.run(host='0.0.0.0',port=80,debug=True)
