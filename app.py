from flask import Flask, render_template, redirect, url_for, session, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate
from forms import RegistrationForm, LoginForm
from sqlalchemy import text


app = Flask(__name__)

app.config['SECRET_KEY'] = 'e8b2fc3ae7e14b1b9e0f2c5a0c9f8f7d'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:1234@localhost/Humans'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')

    def __repr__(self):
        return f"User('{self.username}', '{self.email}')"

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Order(db.Model):
    __tablename__ = 'orders'
    id = db.Column(db.Integer, primary_key=True)
    service_type = db.Column(db.String(50), nullable=False)
    price = db.Column(db.String(20), nullable=False)
    description = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', back_populates='orders')

User.orders = db.relationship('Order', back_populates='user', cascade="all, delete-orphan")


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/services')
def services():
    return render_template('services.html')


@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/contact', methods=['GET'])
def contact():
    return render_template('contact.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user_exists = User.query.filter((User.username == form.username.data) | (User.email == form.email.data)).first()
        if user_exists:
            flash('Пользователь с таким именем или почтой уже существует', 'danger')
            return redirect(url_for('register'))

        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()

        flash('Регистрация успешна! Войдите в систему.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            flash('Вы успешно вошли!', 'success')
            return redirect(url_for('dashboard'))
        flash('Неверный логин или пароль', 'danger')
    return render_template('login.html', form=form)


@app.route('/dashboard')
@login_required
def dashboard():
    user_orders = Order.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', orders=user_orders)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Вы вышли из системы', 'success')
    return redirect(url_for('login'))


@app.route('/create_order', methods=['GET', 'POST'])
@login_required
def create_order():
    if request.method == 'POST':
        service_type = request.form['service_type']
        price = request.form['price']
        description = request.form['description']

        new_order = Order(
            service_type=service_type,
            price=price,
            description=description,
            user_id=current_user.id
        )
        db.session.add(new_order)
        db.session.commit()

        flash('Заказ создан успешно!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('create_order.html')


@app.route('/cancel_order/<int:order_id>', methods=['POST'])
@login_required
def cancel_order(order_id):
    order = Order.query.get(order_id)
    if order and order.user_id == current_user.id:
        db.session.delete(order)
        db.session.commit()
        flash('Заказ отменён', 'success')
    else:
        flash('Ошибка при удалении заказа', 'danger')
    return redirect(url_for('dashboard'))

#2 метода(если данные не верны он не ретернит)
@app.route('/employee_login', methods=['GET', 'POST'])
def employee_login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data) and user.role == 'employee':
            login_user(user)
            flash('Вы вошли как сотрудник!', 'success')
            return redirect(url_for('employee_dashboard'))
        flash('Неверные данные или вы не являетесь сотрудником', 'danger')
    return render_template('employee_login.html', form=form)


@app.route('/employee_dashboard')
@login_required
def employee_dashboard():
    if current_user.role != 'employee':
        flash('Доступ запрещён', 'danger')
        return redirect(url_for('login'))
    return render_template('employee_dashboard.html')


@app.route('/order_list')
@login_required
def order_list():
    if current_user.role != 'employee':
        flash('Доступ запрещён', 'danger')
        return redirect(url_for('login'))
    orders = Order.query.all()
    return render_template('order_list.html', orders=orders)


@app.route('/employee_panel')
@login_required
def employee_panel():
    if current_user.role != 'employee':
        flash('Доступ запрещён', 'danger')
        return redirect(url_for('login'))
    return render_template('employee_dashboard.html')


@app.route('/show_orders')
@login_required
def show_orders():
    if current_user.role != 'employee':
        flash('Доступ запрещён', 'danger')
        return redirect(url_for('login'))
    orders = Order.query.all()
    return render_template('show_orders.html', orders=orders)

@app.route('/execute_sql', methods=['POST'])
@login_required
def execute_sql():
    if current_user.role != 'employee':
        flash('Доступ запрещён', 'danger')
        return redirect(url_for('login'))

    sql_query = request.form.get('sql_query')  # Получаем SQL запрос из формы
    result = None  # Инициализируем переменную для результата

    try:
        # Выполняем SQL запрос
        cursor_result = db.session.execute(text(sql_query))

        # Если результат содержит строки, получаем данные через fetchall
        if cursor_result.returns_rows:
            rows = cursor_result.fetchall()  # Извлекаем все строки
            # Получаем имена колонок из описания результата
            columns = cursor_result.keys()

            # Преобразуем результат в список словарей, где ключи - это имена колонок
            result = [dict(zip(columns, row)) for row in rows]

        db.session.commit()
        flash('Запрос выполнен успешно', 'success')
    except Exception as e:
        flash(f'Ошибка при выполнении запроса: {e}', 'danger')

    return render_template('employee_dashboard.html', result=result)



if __name__ == '__main__':
    app.run(debug=True)
