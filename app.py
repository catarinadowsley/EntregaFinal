
from flask import Blueprint, Flask, request, jsonify, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate

from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity

import cloudinary.uploader
import bcrypt
import jwt 
import datetime
import uuid


app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data-dev.sqlite'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config["JSON_SORT_KEYS"] = False
app.config["SECRET_KEY"] = 'secret'

app.config['JWT_SECRET_KEY'] = app.config["SECRET_KEY"]

user_api = Blueprint('user_api', __name__)

db = SQLAlchemy(app)
migrate = Migrate(app, db)
jwt = JWTManager(app)


#Criando a classe de todos os usuários do site
class User(db.Model):

    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(20), unique=True, nullable=False)
    idade = db.Column(db.Integer, default=0)
    address= db.Column(db.String(500), nullable =False)
    password_hash= db.Column(db.String(128), nullable=False)
    active = db.Column(db.Boolean, default=False)

    def json(self):
        user_json = {'id': self.id,
                     'name': self.name,
                     'email': self.email,
                     'idade': self.idade,
                     'address': self.address
                     }
        return user_json
      

class Report(db.Model):
    __tabelname__ = 'messages'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(20), unique=True, nullable=False)
    message=db.Column(db.String(10000), nullable = False)
   
    def json(self):
        message_json = {'id': self.id,
                     'name': self.name,
                     'email': self.email,
                     'message':self.message
                     }
        return message_json



class Product(db.Model):

    __tablename__ = 'products'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20), nullable=False)
    price = db.Column(db.Integer, nullable=False)
    description = db.Column(db.String(200), nullable=False)

    def json(self):

        return {
                'name': self.name,
                'desciption': self.description,
                'id': self.id,
                'price': self.price
                }







#Fazer Login
@app.route('/login/', methods=['POST'])
def login():

    data = request.json
    
    email = data.get('email')
    password = data.get('password')

    user = User.query.filter_by(email=email).first()
    
    if not bcrypt.checkpw(password.encode(), user.password_hash) or not user:
        return {"msg":"email ou senha inválidos"}, 400 

   
    access_token = create_access_token(identity=user)
   
    return {'msg': "Você está logado !" } , 200







#Criando um usuário
@app.route('/users/', methods=['POST'])
def create_users():

    data = request.json

    name = data.get('name')
    email = data.get('email')
    idade = data.get('idade')
    address = data.get('address')
    password = data.get('password')
    
    if not name or not email  or not idade or not address or not password:
        return {'error': 'Dados insuficientes'}, 400

    user_check = User.query.filter_by(email=email).first()

    if user_check:
        return {'error': 'Usuario já cadastrado'}, 400
    
     

    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

    user = User(name=name, email=email, idade=idade, address= address,
                password_hash=password_hash)

    db.session.add(user)
    db.session.commit()

    return user.json(), 200

    token = create_access_token(identity=user.id)



#Recebe mensagem dos usuários(qualquer tiopo de mensagem-SAC)
@app.route('/users/<int:id>/messages/', methods=['POST'])
@jwt_required
def messages_users():

    data = request.json

    name = data.get('name')
    email = data.get('email')
    message = data.get('message')
    
    if not name or not email  or not message :
        return {'error': 'Dados insuficientes'}, 400

    writer = User.query.get_or_404(id)

    message = Report(name=name, email=email, message=message, writer=writer.id)

    db.session.add(message)
    db.session.commit()

    return user.json(), 200


#Usuário fazendo alterações em seus dados
@app.route('/users/<int:id>', methods=['GET', 'PUT', 'PATCH', 'DELETE'])
@jwt_required
def user_detail(id):
    if request.method == 'GET':
        
        user = User.query.get_or_404(id)
 
        return user.json(), 200
    if request.method == 'PUT':

        data = request.json
        user = User.query.filter_by(id=id).first()

        # novos dados
        new_name = data.get('user')
        new_name = data.get('name')
        new_email = data.get('email')
        new_age = data.get('idade')
        new_address = data.get('address')

        if (not new_name) or (not new_name) or (not new_age) or (not new_address):
            return{'erro':'Dados insuficientes'}, 406

        if User.query.filter_by(email=new_email).first() and new_email != user.email:
            return {'error': 'Email já cadastrado'}, 400
        # replacing data
        user.name = new_name
        user.idade = new_age
        user.email = new_email
        user.address = new_adress
        db.session.add(user)
        db.session.commit()#isso foi para atualizar os dados no database
        return user.json(), 200 


    if request.method == 'PATCH':

        data = request.json
        user = User.query.filter_by(id=id).first()
        new_name = data.get('name')
        new_email = data.get('email')
        new_age = data.get('idade')
        new_adress = data.get('adsress')

        if User.query.filter_by(email=new_email).first() and new_email != user.email:
            return {'error': 'Email já cadastrado'}, 400
        if new_name:
            user.name = new_name
        if new_age:
            user.idade = new_age
        if new_email:
            user.email = new_email
        if new_address:
            user.address = new_adress
        db.session.commit()
        return user.json(), 200


    if request.method == 'DELETE':
        user = User.query.get_or_404(id)
        db.session.delete(user)
        db.session.commit()
        return {}, 204 







@app.route('/users/activate/<token>', methods=['GET'])
def activate(token):

    data = decode_token(token)

    user = User.query.get_or_404(data['identity'])

    if user.active == False:
        user.active = True
        db.session.add(user)
        db.session.commit()

        return {'Ativado!'}


#Um funcionário (específico) pode colocar um produto novo
@app.route('/users/<int:id>/product', methods=['POST'])
def post_new_products():
    #colocar uma condição relacionada ao id em que só funcionários específicos possam ter acesso a função
    
    data = request.json

    name = data.get('name')
    description= data.get('description')
    price= data.get('price')
    #photo
   
    
    if not name or not description  or not price :
        return {'error': 'Dados insuficientes'}, 400

    product_check = Product.query.filter_by(name=name).first()

    if user_check:
        return {'error': 'Já existe um produto com esse nome!'}, 400


    product = Product(name=name, description=description, price=price)

    db.session.add(product)
    db.session.commit()

    return user.json(), 200


    


if __name__ == '__main__':
    app.run(debug=True)


    ##Eu tive um problema com o python no meu computador. EU não consigo rodar o arquivo de jeito nenhum. Quando eu uso pipenv install flask ele diz que eu não tenho a versão 3.7 do python só que eu nunca tive esse problema ate agora.