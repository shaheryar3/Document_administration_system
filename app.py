from flask import Flask, render_template, url_for, redirect, request, jsonify,render_template,send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from hashlib import sha256
from datetime import datetime
from werkzeug.utils import secure_filename
import os

app = Flask(__name__)

bcrypt = Bcrypt(app)
app.config['UPLOAD_FOLDER'] = 'C:/fin_prod/'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'thisisasecretkey'
db = SQLAlchemy(app)
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
class Doc(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ipfs_hash = db.Column(db.String(255))
    filename = db.Column(db.String(255),unique = True)
    content = db.Column(db.LargeBinary)
    pdf_path = db.Column(db.String(255)) # new field for storing PDF path
class Document:
    def __init__(self, content):
        self.content = content
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        content_str = str(self.content)
        return sha256(content_str.encode('utf-8')).hexdigest()


class Blockchain:
    def __init__(self):
        self.chain = []

    def add_document(self, document):
        previous_hash = self.chain[-1].hash if self.chain else None
        self.chain.append(document)
        print("Document added to the blockchain.")

    def verify_document(self, document):
        for i in range(len(self.chain)):
            if document.hash == self.chain[i].hash:
                print("Document is verified and unchanged.")
                return True
        print("Document verification failed.")
        return False
    
    def delete_document(self, document):
         for i in range(len(self.chain)):
            if document.hash == self.chain[i].hash:
                del self.chain[i]
                print("Document deleted from the blockchain.")
                return True
         print("Document not found on the blockchain.")
         return False

blockchain = Blockchain()
with app.app_context():
    db.create_all()
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))





class RegisterForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                'That username already exists. Please choose a different one.')


class LoginForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Login')


@app.route('/')
def home():
    return render_template('home.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
    return render_template('login.html', form=form)


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    documents = Doc.query.all()
    
    return render_template('dashboard.html',documents=documents)


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@ app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html', form=form)
@app.route('/add_document', methods=['POST'])
def add_document():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided.'}), 400
    
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({'error': 'No selected file.'}), 400
    content = file.read()
    print(str(content).encode('utf-8'))

    
    document = Document(content)
    if blockchain.verify_document(document):
        return jsonify({'message':'Document already added to blockchain'})
    print(document.hash)
    
    blockchain.add_document(document)
    
    filename = secure_filename(file.filename)
    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    pdf_path = 'C:/fin_prod/' + filename # replace with actual path to PDF directory
    print(pdf_path)
    doc = Doc(filename=file.filename, content=file.read(), pdf_path=pdf_path)
    db.session.add(doc)
    db.session.commit()
    
    
    # Store IPFS hash in database
    try:
        client = ipfshttpclient.connect()
        res = client.add(pdf_path)
        doc.ipfs_hash = res['Hash']
        db.session.commit()
    except:
        pass
    
    
   
    
    return jsonify({'message': 'Document added to the blockchain.'}), 200


@app.route('/verify_document', methods=['POST'])
def verify_document():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided.'}), 400
    
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({'error': 'No selected file.'}), 400
    
    content = file.read()
    print(str(content).encode('utf-8'))
    print("hello")
    document = Document(content)
    print(document.hash)
    
    if blockchain.verify_document(document):
        return jsonify({'message': 'Document is verified and unchanged.'}), 200
    else:
        return jsonify({'message': 'Document verification failed.'}), 400

@app.route('/delete_document', methods=['POST'])
def delete_document():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided.'}), 400
    
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({'error': 'No selected file.'}), 400
    
    content = file.read()
    document = Document(content)
    
    if blockchain.delete_document(document):
        return jsonify({'message': 'Document deleted from the blockchain.'}), 200
    else:
        return jsonify({'message': 'Document not found on the blockchain.'}), 400
@app.route('/add_document')
def add_document_page():
    return render_template('add_document.html')

@app.route('/verify_document')
def verify_document_page():
    return render_template('verify_document.html')

@app.route('/delete_document')
def delete_document_page():
    return render_template('delete_document.html')
@app.route("/download-pdf/<int:doc_id>")
def download_pdf(doc_id):
    doc = Doc.query.get_or_404(doc_id)
    print(doc.pdf_path)
    return send_file(doc.pdf_path,  as_attachment=True)


if __name__ == '__main__':
    app.run(debug=True)


if __name__ == "__main__":
    app.run(debug=True)
