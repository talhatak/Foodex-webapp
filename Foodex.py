from flask import Flask, flash, redirect, render_template, url_for, request, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_migrate import Migrate, MigrateCommand
from flask_script import Manager
from datetime import datetime
from flask_wtf import FlaskForm
from wtforms import StringField, IntegerField, TextAreaField, HiddenField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_wtf.file import FileField, FileAllowed
import random
from flask_bcrypt import Bcrypt
from flask_mail import Mail
from flask_uploads import UploadSet, configure_uploads, IMAGES

app = Flask(__name__, template_folder='templates')

photos = UploadSet('photos', IMAGES)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOADED_PHOTOS_DEST'] = 'images' 
app.config.update(
    MAIL_SERVER = 'smtp.gmail.com',
    MAIL_PORT = '465',
    MAIL_USE_SSL = True,
    MAIL_USERNAME = 'nightsafari3@gmail.com',
    MAIL_PASSWORD = 'eligthafogqrujvq'
)
app.config["SQLALCHEMY_DATABASE_URI"] = 'mysql://root:@localhost/foodex'    ### DATABSE CONNECTED -- DATABASE NAME: foodex
app.config['SECRET_KEY'] = 'mysecret'
configure_uploads(app, photos)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

mail = Mail(app)
db = SQLAlchemy(app)
migrate = Migrate(app, db)

manager = Manager(app)
manager.add_command('db', MigrateCommand)


class Contacts(db.Model):       ### TABLE NAME IN WHICH FEEDBACK IS STORED!
    ### sno, name, email, msg, date
    sno = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(50), nullable=False)
    msg = db.Column(db.String(200), nullable=False)
    date = db.Column(db.String, nullable=True)

@app.route("/", methods = ['GET', 'POST'])      ### HOME PAGE
def home():
    if (request.method=='POST'):
        name = request.form.get('name')     ### ADD entry to database
        email = request.form.get('email')
        msg = request.form.get('msg')

        entry = Contacts(name = name, email = email, date = datetime.now(), msg = msg)
        db.session.add(entry)
        db.session.commit()
        mail.send_message('New Foodex subscriber: ' + name, sender = email, recipients = ['nightsafari3@gmail.com'], body = msg)
    
    return render_template('index.html')

class User(db.Model, UserMixin):        ###DATABASE TO STORE USER DATA
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)


class RegisterForm(FlaskForm):          ###REGISTRATION FORM
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    c_password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Confirm Password"})

    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                'That username already exists. Please choose a different one.')


class LoginForm(FlaskForm):             ###LOGIN FORM
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Login')

class Product(db.Model):            ###PRODUCT TABLE STORES PRODUCT INFORMATION
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True)
    price = db.Column(db.Integer)  # in cents
    stock = db.Column(db.Integer)
    description = db.Column(db.String(500))
    image = db.Column(db.String(100))

    orders = db.relationship('Order_Item', backref='product', lazy=True)

    def in_stock(self):
        if session:
            item = []
            try:
                item = session['cart']
            except:
                pass
            inde = 0
            if len(item) > 0:
                for ind, it in enumerate(item):
                    if it.get('id') == self.id:
                        inde = ind
                return self.stock - item[inde].get('quantity')
            else:
                return self.stock
        else:
            return self.stock


class Order(db.Model):              ### ORDER TABLE TO STORE ORDER
    id = db.Column(db.Integer, primary_key=True)
    reference = db.Column(db.String(5))
    first_name = db.Column(db.String(20))
    last_name = db.Column(db.String(20))
    phone_number = db.Column(db.Integer)
    email = db.Column(db.String(50))
    address = db.Column(db.String(100))
    status = db.Column(db.String(10))
    items = db.relationship('Order_Item', backref='order', lazy=True)

    def order_total(self):
        return db.session.query(db.func.sum(Order_Item.quantity * Product.price)).join(Product).filter(Order_Item.order_id == self.id).scalar() + 100

    def quantity_total(self):
        return db.session.query(db.func.sum(Order_Item.quantity)).filter(Order_Item.order_id == self.id).scalar()


class Order_Item(db.Model):         ### ORDER_ITEM TO STORE ITEM ORDERED BY THE CUSTOMER.
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'))
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'))
    quantity = db.Column(db.Integer)


class AddProduct(FlaskForm):            ### ADD PRODUCT TO INVENTORY
    name = StringField('Name')
    price = IntegerField('Price')
    stock = IntegerField('Stock')
    description = TextAreaField('Description')
    image = FileField('Image')


class AddToCart(FlaskForm):         ### ADD ITEM TO CART
    quantity = IntegerField('Quantity')
    id = HiddenField('ID')


class Checkout(FlaskForm):          ### CHECKOUT FORM
    first_name = StringField('First Name')
    last_name = StringField('Last Name')
    phone_number = StringField('Number')
    email = StringField('Email')
    address = StringField('Address')


def handle_cart():
    products = []
    grand_total = 0
    index = 0
    quantity_total = 0

    for item in session['cart']:
        product = Product.query.filter_by(id=item['id']).first()

        quantity = int(item['quantity'])
        total = quantity * product.price
        grand_total += total

        quantity_total += quantity

        products.append({'id': product.id, 'name': product.name, 'price':  product.price,
                         'image': product.image, 'quantity': quantity, 'total': total, 'index': index})
        index += 1

    grand_total_plus_shipping = grand_total + 100

    return products, grand_total, grand_total_plus_shipping, quantity_total


@app.route('/login', methods=['GET', 'POST'])
def login():               ### LOGIN FORM
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                flash("Login Successful!")
                return redirect(url_for('index'))
    return render_template('login.html', form=form)

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():           ### LOGOUT FORM
    logout_user()
    flash("Logut Successsful!")
    return redirect(url_for('login'))

@ app.route('/register', methods=['GET', 'POST'])
def register():            ### REGISTER YOURSELF
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html', form=form)

@app.route('/product', methods=['POST', "GET"])
def index():            ### PRODUCT PAGE
    products = Product.query.all()

    return render_template('product.html', products=products)


@app.route('/product/<id>')
def product(id):        ### VIEW PRODUCT PAGE
    product = Product.query.filter_by(id=id).first()

    form = AddToCart()

    return render_template('view-product.html', product=product, form=form)


@app.route('/quick-add/<id>')
def quick_add(id):          
    if 'cart' not in session:
        session['cart'] = []

    session['cart'].append({'id': id, 'quantity': 1})
    session.modified = True

    return redirect(url_for('index'))


@app.route('/add-to-cart', methods=['POST'])
def add_to_cart():
    if 'cart' not in session:
        session['cart'] = []

    form = AddToCart()

    if form.validate_on_submit():

        session['cart'].append(
            {'id': form.id.data, 'quantity': form.quantity.data})
        session.modified = True

    return redirect(url_for('index'))


@app.route('/cart')
def cart():     ### CART PAGE
    products, grand_total, grand_total_plus_shipping, quantity_total = handle_cart()

    return render_template('cart.html', products=products, grand_total=grand_total, grand_total_plus_shipping=grand_total_plus_shipping, quantity_total=quantity_total)


@app.route('/remove-from-cart/<index>')
def remove_from_cart(index):            ### REMOVE FROM CART BUTTON
    del session['cart'][int(index)]
    session.modified = True
    return redirect(url_for('cart'))

@app.route('/mark-order-completed/<index>')
def mark_order_completed(index):            ### MARK ORDER COMPLETED
    order_to_delete = Order.query.filter_by(id=int(index)).first()
    db.session.delete(order_to_delete)
    db.session.commit()
    session.modified = True
    flash("Order completed!")       ### FLASH MESSAGE
    return redirect(url_for('admin', order=order, admin=True))


@app.route('/checkout', methods=['GET', 'POST'])
def checkout():             ### CHECKOUT BUTTON
    form = Checkout()

    products, grand_total, grand_total_plus_shipping, quantity_total = handle_cart()

    if form.validate_on_submit():

        order = Order()
        form.populate_obj(order)
        order.reference = ''.join([random.choice('ABCDE') for _ in range(5)])
        order.status = 'PENDING'

        for product in products:
            order_item = Order_Item(
                quantity=product['quantity'], product_id=product['id'])
            order.items.append(order_item)

            product = Product.query.filter_by(id=product['id']).update(
                {'stock': Product.stock - product['quantity']})

        db.session.add(order)
        db.session.commit()
        flash("Order Submitted!")       ### FLASH MESSAGE

        session['cart'] = []
        session.modified = True

        return redirect(url_for('index'))

    return render_template('checkout.html', form=form, grand_total=grand_total, grand_total_plus_shipping=grand_total_plus_shipping, quantity_total=quantity_total)


@app.route('/admin')
def admin():        ### ADMIN PAGE
    products = Product.query.all()
    products_in_stock = Product.query.filter(Product.stock > 0).count()

    orders = Order.query.all()

    return render_template('admin/index.html', admin=True, products=products, products_in_stock=products_in_stock, orders=orders)


@app.route('/admin/add', methods=['GET', 'POST'])
def add():          ### ADD PRODUCT TO INVENTORY - PAGE
    form = AddProduct()

    if form.validate_on_submit():
        image_url = photos.url(photos.save(form.image.data))

        new_product = Product(name=form.name.data, price=form.price.data,
                              stock=form.stock.data, description=form.description.data, image=image_url)

        db.session.add(new_product)
        db.session.commit()

        return redirect(url_for('admin'))

    return render_template('admin/add-product.html', admin=True, form=form)


@app.route('/admin/order/<order_id>')
def order(order_id):
    order = Order.query.filter_by(id=int(order_id)).first()

    return render_template('admin/view-order.html', order=order, admin=True)

if __name__=='__main__':
    app.run(debug=True)