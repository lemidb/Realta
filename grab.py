from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
import os

# Create Flask app instance
app = Flask(__name__)

# Configure SQLite database
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'data.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'super-secret-key'  # Change this in production!

# Initialize extensions
db = SQLAlchemy(app)
jwt = JWTManager(app)

class User(db.Model):
    """User model for authentication"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    
    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        self.password = generate_password_hash(self.password)
        
    def check_password(self, password):
        return check_password_hash(self.password, password)

class Item(db.Model):
    """Item model for storing data"""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    value = db.Column(db.String(200))
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    
@app.route('/auth/register', methods=['POST'])
def register():
    """
    Register a new user
    Request Body: {'username': string, 'password': string}
    Returns: JSON response with success message
    """
    data = request.json
    if not data.get('username') or not data.get('password'):
        return jsonify({"error": "Username and password required"}), 400
        
    existing_user = User.query.filter_by(username=data['username']).first()
    if existing_user:
        return jsonify({"error": "Username already exists"}), 400
        
    new_user = User(username=data['username'], password=data['password'])
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "User created successfully"}), 201

@app.route('/auth/login', methods=['POST'])
def login():
    """
    Login endpoint to get JWT token
    Request Body: {'username': string, 'password': string}
    Returns: JSON response with JWT token
    """
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    user = User.query.filter_by(username=username).first()
    if not user or not user.check_password(password):
        return jsonify({"error": "Invalid credentials"}), 401
    
    access_token = create_access_token(identity=username)
    return jsonify(access_token=access_token), 200

@app.route('/api/data', methods=['GET'])
@jwt_required()
def get_all_data():
    """
    Get all items for current user
    Requires valid JWT token in Authorization header
    Returns: List of items belonging to authenticated user
    """
    current_user = get_jwt_identity()
    items = Item.query.filter_by(owner_id=User.query.filter_by(username=current_user).first().id).all()
    return jsonify([{"id": item.id, "name": item.name, "value": item.value} for item in items])

@app.route('/api/data/<int:item_id>', methods=['GET'])
@jwt_required()
def get_item(item_id):
    """
    Get specific item
    Requires valid JWT token in Authorization header
    Returns: Single item object
    """
    current_user = get_jwt_identity()
    user_id = User.query.filter_by(username=current_user).first().id
    item = Item.query.filter_by(id=item_id, owner_id=user_id).first()
    
    if not item:
        return jsonify({"error": "Item not found"}), 404
        
    return jsonify({"id": item.id, "name": item.name, "value": item.value})

@app.route('/api/data', methods=['POST'])
@jwt_required()
def create_item():
    """
    Create new item
    Requires valid JWT token in Authorization header
    Request Body: {'name': string, 'value': string}
    Returns: Created item with ID
    """
    data = request.json
    if not data.get('name'):
        return jsonify({"error": "Name field is required"}), 400
        
    current_user = get_jwt_identity()
    user_id = User.query.filter_by(username=current_user).first().id
    
    new_item = Item(name=data['name'], value=data.get('value'), owner_id=user_id)
    db.session.add(new_item)
    db.session.commit()
    
    return jsonify({
        "id": new_item.id,
        "name": new_item.name,
        "value": new_item.value
    }), 201

@app.route('/api/data/<int:item_id>', methods=['PUT'])
@jwt_required()
def update_item(item_id):
    """
    Update existing item
    Requires valid JWT token in Authorization header
    Request Body: {'name': string, 'value': string}
    Returns: Updated item
    """
    current_user = get_jwt_identity()
    user_id = User.query.filter_by(username=current_user).first().id
    
    item = Item.query.filter_by(id=item_id, owner_id=user_id).first()
    if not item:
        return jsonify({"error": "Item not found"}), 404
        
    data = request.json
    if 'name' in data:
        item.name = data['name']
    if 'value' in data:
        item.value = data['value']
        
    db.session.commit()
    return jsonify({
        "id": item.id,
        "name": item.name,
        "value": item.value
    })

@app.route('/api/data/<int:item_id>', methods=['DELETE'])
@jwt_required()
def delete_item(item_id):
    """
    Delete item
    Requires valid JWT token in Authorization header
    Returns: Success message
    """
    current_user = get_jwt_identity()
    user_id = User.query.filter_by(username=current_user).first().id
    
    item = Item.query.filter_by(id=item_id, owner_id=user_id).first()
    if not item:
        return jsonify({"error": "Item not found"}), 404
        
    db.session.delete(item)
    db.session.commit()
    return jsonify({"message": "Item deleted successfully"}), 200

@app.before_request
def setup_database():
    """Initialize database tables"""
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)