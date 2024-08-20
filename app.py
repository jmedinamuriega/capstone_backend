from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS
from sqlalchemy.exc import IntegrityError
from datetime import datetime
from flask_migrate import Migrate
import os



app = Flask(__name__)
CORS(app)


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///capstone.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'Gringochone0'
app.config['JWT_SECRET_KEY'] = 'Gringochone0'

db = SQLAlchemy(app)

bcrypt = Bcrypt(app)
jwt = JWTManager(app)
migrate = Migrate(app, db)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)

class Service(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    service_type = db.Column(db.String(50), nullable=False)
    big_item = db.Column(db.Boolean, default=False)
    delivery = db.Column(db.Boolean, default=False)
    pickup = db.Column(db.Boolean, default=False)
    location = db.Column(db.String(200), nullable=True)
    pickup_date = db.Column(db.DateTime, nullable=True)  
    delivery_date = db.Column(db.DateTime, nullable=True)  
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref=db.backref('services', lazy=True))


    user = db.relationship('User', backref=db.backref('services', lazy=True))

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    new_user = User(username=data['username'], email=data['email'], password=hashed_password)
    try:
        db.session.add(new_user)
        db.session.commit()
        return jsonify(message="User registered successfully"), 201
    except IntegrityError:
        return jsonify(message="User already exists"), 409

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(email=data['email']).first()
    if user and bcrypt.check_password_hash(user.password, data['password']):
        access_token = create_access_token(identity=user.id)
        return jsonify(access_token=access_token, username=user.username), 200
    else:
        return jsonify(message="Invalid credentials"), 401


@app.route('/services', methods=['POST'])
@jwt_required()
def add_service():
    data = request.get_json()
    user_id = get_jwt_identity()
    new_service = Service(
        user_id=user_id,
        service_type=data['service_type'],
        big_item=data.get('big_item', False),
        delivery=data.get('delivery', False),
        pickup=data.get('pickup', False),
        location=data.get('location'),
        pickup_date=datetime.strptime(data['pickup_date'], '%Y-%m-%d') if data.get('pickup_date') else None,
        delivery_date=datetime.strptime(data['delivery_date'], '%Y-%m-%d') if data.get('delivery_date') else None,
    )
    db.session.add(new_service)
    db.session.commit()
    return jsonify(message="Service added successfully"), 201


@app.route('/services', methods=['GET'])
@jwt_required()
def get_services():
    user_id = get_jwt_identity()
    services = Service.query.filter_by(user_id=user_id).all()
    return jsonify(services=[{
        'id': service.id,
        'service_type': service.service_type,
        'big_item': service.big_item,
        'delivery': service.delivery,
        'pickup': service.pickup,
        'location': service.location,
        'pickup_date': service.pickup_date.strftime('%Y-%m-%d') if service.pickup_date else None,
        'delivery_date': service.delivery_date.strftime('%Y-%m-%d') if service.delivery_date else None,
        'timestamp': service.timestamp
    } for service in services]), 200

    
@app.route('/update_account', methods=['PUT'])
@jwt_required()
def update_account():
    user_id = get_jwt_identity()
    data = request.get_json()
    user = User.query.get(user_id)

    if user:
        user.username = data.get('username', user.username)
        user.email = data.get('email', user.email)
        try:
            db.session.commit()
            return jsonify(message="Account updated successfully"), 200
        except IntegrityError:
            return jsonify(message="Username or email already taken"), 409
    else:
        return jsonify(message="User not found"), 404

@app.route('/delete_account', methods=['DELETE'])
@jwt_required()
def delete_account():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    if user:
        db.session.delete(user)
        db.session.commit()
        return jsonify(message="Account deleted successfully"), 200
    else:
        return jsonify(message="User not found"), 404

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=port)