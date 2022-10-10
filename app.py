from flask import Flask, render_template, redirect, url_for, Blueprint, flash, Response, request
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, FileField, IntegerField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy import *
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime
from time import strftime
from datetime import datetime
from base64 import b64encode
import base64
from io import BytesIO
from werkzeug.utils import secure_filename
import os

'import web3.eth'
from web3 import Web3
import json
from web3.middleware import geth_poa_middleware

url = "https://ropsten.infura.io/v3/9aa3d95b3bc440fa88ea12eaa4456161"
web3 = Web3(Web3.HTTPProvider(url))
web3.middleware_onion.inject(geth_poa_middleware, layer=0)
abi = json.loads('[{"constant":true,"inputs":[],"name":"name","outputs":[{"name":"","type":"string"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"spender","type":"address"},{"name":"tokens","type":"uint256"}],"name":"approve","outputs":[{"name":"success","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"totalSupply","outputs":[{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"from","type":"address"},{"name":"to","type":"address"},{"name":"tokens","type":"uint256"}],"name":"transferFrom","outputs":[{"name":"success","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"decimals","outputs":[{"name":"","type":"uint8"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"_totalSupply","outputs":[{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"name":"tokenOwner","type":"address"}],"name":"balanceOf","outputs":[{"name":"balance","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"symbol","outputs":[{"name":"","type":"string"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"name":"a","type":"uint256"},{"name":"b","type":"uint256"}],"name":"safeSub","outputs":[{"name":"c","type":"uint256"}],"payable":false,"stateMutability":"pure","type":"function"},{"constant":false,"inputs":[{"name":"to","type":"address"},{"name":"tokens","type":"uint256"}],"name":"transfer","outputs":[{"name":"success","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[{"name":"a","type":"uint256"},{"name":"b","type":"uint256"}],"name":"safeDiv","outputs":[{"name":"c","type":"uint256"}],"payable":false,"stateMutability":"pure","type":"function"},{"constant":true,"inputs":[{"name":"a","type":"uint256"},{"name":"b","type":"uint256"}],"name":"safeMul","outputs":[{"name":"c","type":"uint256"}],"payable":false,"stateMutability":"pure","type":"function"},{"constant":true,"inputs":[{"name":"tokenOwner","type":"address"},{"name":"spender","type":"address"}],"name":"allowance","outputs":[{"name":"remaining","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"name":"a","type":"uint256"},{"name":"b","type":"uint256"}],"name":"safeAdd","outputs":[{"name":"c","type":"uint256"}],"payable":false,"stateMutability":"pure","type":"function"},{"inputs":[],"payable":false,"stateMutability":"nonpayable","type":"constructor"},{"anonymous":false,"inputs":[{"indexed":true,"name":"from","type":"address"},{"indexed":true,"name":"to","type":"address"},{"indexed":false,"name":"tokens","type":"uint256"}],"name":"Transfer","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"name":"tokenOwner","type":"address"},{"indexed":true,"name":"spender","type":"address"},{"indexed":false,"name":"tokens","type":"uint256"}],"name":"Approval","type":"event"}]')
token_address = "0xe1E72b7D424A19fA86A022C3B8410DFaE4ff1a16"
contract = web3.eth.contract(address=token_address,abi=abi)

views = Blueprint("views", __name__)
app = Flask(__name__, template_folder='template')
app.config['SECRET_KEY'] = 'Hungtech-Teenagercoin-Site-System-2810'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
db.init_app(app)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(80), unique=True)
    address = db.Column(db.String(45), unique=True)
    password = db.Column(db.String(80))

    def __repr__(self):
        return '<User {}>'.format(self.username)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))



@app.route('/')
def index():
    "eth_balanced = web3.toChecksumAddress()"
    return render_template("index.html")

@login_required
@app.route('/dashboard')
def dashboard():
    eth_balanced = float(web3.toWei(web3.eth.getBalance(current_user.address),'ether'))
    teen_balanced = float(web3.toWei(contract.functions.balanceOf(current_user.address).call(),'ether'))
    print(eth_balanced,teen_balanced)
    return render_template("dashboard.html",eth_balanced=eth_balanced,teen_balanced=teen_balanced)


@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()

        # check if the user actually exists
        # take the user-supplied password, hash it, and compare it to the hashed password in the database
        if not user or not check_password_hash(user.password, password):
            flash('Please check your login details and try again.')
            return redirect(url_for('login'))
        else:
            login_user(user)
            return redirect(url_for('dashboard'))

    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        # code to validate and add user to database goes here
        username = request.form.get('user')
        email = request.form.get('email')
        address = request.form.get('address')
        password = request.form.get('password')

        user = User.query.filter_by(
            email=email).first()  # if this returns a user, then the email already exists in database

        if user:
            flash('Tài khoản đã tồn tại')   # if a user is found, we want to redirect back to signup page so user can try again
            return redirect(url_for('signup'))
        hashpass = generate_password_hash(password, method='sha256')
        # create a new user with the form data. Hash the password so the plaintext version isn't saved.
        new_user = User(email=email, username=username,address=address, password=hashpass)
        # add the new user to the database
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('dashboard'))
    return render_template('register.html')

@login_required
@app.route('/transfer/by/real/address', methods=['GET', 'POST'])
def transfer():
    if request.method == 'POST':
        add = current_user.address
        to_add = request.form.get('to_address')
        private_key = request.form.get('private_key')
        value = int(request.form.get('value'))
        test = os.environ[add+to_add] = private_key
        test2 = os.getenv(add+to_add)
        tran = contract.functions.transfer(to_add, web3.toWei(value, 'ether')).buildTransaction(
            {'chainId': 3, 'gas': 3000000, 'nonce': web3.eth.getTransactionCount(add), 'value': 0})
        signed_txn = web3.eth.account.signTransaction(tran, test2)
        web3.eth.sendRawTransaction(signed_txn.rawTransaction)

    return render_template('transfer1.html')

@login_required
@app.route('/transfer/by/teensystem/address', methods=['GET', 'POST'])
def teen_transfer():
    if request.method == 'POST':
        add = current_user.address
        to_add = request.form.get('to_address')
        private_key = request.form.get('private_key')
        value = int(request.form.get('value'))
        test = os.environ[add+to_add] = private_key
        test2 = os.getenv(add+to_add)
        real_to_add = User.query.filter_by(id=to_add).first()
        tran = contract.functions.transfer(real_to_add.address, web3.toWei(value, 'ether')).buildTransaction(
            {'chainId': 3, 'gas': 3000000, 'nonce': web3.eth.getTransactionCount(add), 'value': 0})
        signed_txn = web3.eth.account.signTransaction(tran, test2)
        web3.eth.sendRawTransaction(signed_txn.rawTransaction)

    return render_template('transfer.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

"""
tx = {
    'chainId': 3,
    'nonce': nonce,
    'to': recadd,
    'value': 0,
    'gas': 2000000,
    'gasPrice': web3.eth.gasPrice
}
"""

"""
signed_txn = web3.eth.account.signTransaction(tran, priv)
web3.eth.sendRawTransaction(signed_txn.rawTransaction)

print(f"My balance: {float(web3.fromWei(contact.functions.balanceOf(acc).call(),'ether'))}")
print(f"Receiver balance: {float(web3.fromWei(contact.functions.balanceOf(recadd).call(),'ether'))}")
"""

if __name__ == '__main__':
    app.run(debug=True)
