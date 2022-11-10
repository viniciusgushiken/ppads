from flask import Flask, render_template, request, redirect, url_for
import requests
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt


#from . import db
# import sys

app = Flask(__name__)

bcrypt = Bcrypt(app) # para hashear a senha
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'thisisasecretkey'
db = SQLAlchemy(app) # cria a instancia do db

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)


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
def index():
    return render_template("index.html")

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first() # se usuario existe no db
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('simulador'))
    return render_template('login.html', form=form)

@app.route('/cadastro', methods=['GET', 'POST'])
def cadastro():
	form = RegisterForm()
    
	if form.validate_on_submit():
		hashed_password = bcrypt.generate_password_hash(form.password.data)
		new_user = User(username=form.username.data, password=hashed_password)
		db.session.add(new_user)
		db.session.commit()

		return redirect(url_for('login'))

	return render_template("register.html", form=form)


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.errorhandler(500)
def internal_error(error):
	return render_template('500.html'),500


@app.route('/simulador')
def simulador():
	return render_template("simulador.html")

@app.route('/calcular', methods=['POST'])
def calcular():
	ticker = request.form['ticker']
	valor_inicial = float(request.form['valor'])
	data_inicial = request.form['data_inicial']
	data_final = request.form['data_final']
	data_inicial_fds = datetime.strptime(data_inicial, "%Y-%m-%d").weekday()
	data_final_fds = datetime.strptime(data_final, "%Y-%m-%d").weekday()
	
	# # verifica se as datas de input nao é fim de semana
	# if (data_inicial_fds > 5) or (data_final_fds > 5):
	# 	sys.exit("Favor não inserir datas de fim de semanas, insira novamente as datas")
	# 	flash('Favor não inserir datas de fim de semanas, insira novamente as datas')
	
	url = 'https://www.alphavantage.co/query?function=TIME_SERIES_DAILY_ADJUSTED&symbol='+ticker+'&apikey=ZNAHP2SA68BJ5XGR&outputsize=full'
	r = requests.get(url)
	data = r.json()
	
	#todas as datas da acao
	lista_dias = list(data["Time Series (Daily)"].keys())
	
	primeiro_dia_cotacao = lista_dias[-1]
	ultimo_dia_cotacao = lista_dias[0]
	
	lista_valor_acao = []

	# todos os valores de fechamento da acao
	for dia in lista_dias:	
		valor_acao = data["Time Series (Daily)"][dia]["4. close"]
		lista_valor_acao.append(float(valor_acao))

	# criando dict dia:valor
	dia_acao = dict(zip(lista_dias,lista_valor_acao))
	
	valor_acao_data_inicial = dia_acao.get(data_inicial)
	valor_acao_data_final = dia_acao.get(data_final)
	
# #verifica se as datas de input estao presentes na lista de dias de cotacao
# 	if (valor_acao_data_inicial == None) or (data_final_fds == None):
# 		sys.exit("Não achamos cotação para essas datas, talvez seja um dia de feriado! Ou essa ação ainda não existia nessa data. Essas são as datas inicias e finais que possuímos "+primeiro_dia_cotacao+" e "+ultimo_dia_cotacao)
# 		flash("Não achamos cotação para essas datas, talvez seja um dia de feriado! Ou essa ação ainda não existia nessa data. Essas são as datas inicias e finais que possuímos "+primeiro_dia_cotacao+" e "+ultimo_dia_cotacao)
	
	valorizacao = ( (valor_acao_data_final / valor_acao_data_inicial ) - 1 )
	valorizacao_porcentagem = round( ( valorizacao * 100 ) , 2 )
	
	valor_final = round( valor_inicial * (1+valorizacao) , 2 )
	
	lucro = round( ( valor_final - valor_inicial ) , 2 )
	
	return render_template("resposta.html", 
												 ticker=ticker, 
												 valor_inicial=valor_inicial, 
												 data_inicial=data_inicial,
												 valor_acao_data_inicial=valor_acao_data_inicial,
												 data_final=data_final,
												 valor_acao_data_final=valor_acao_data_final,
												 valorizacao_porcentagem=valorizacao_porcentagem,
												 valor_final=valor_final, 
												 lucro=lucro)


if __name__ == "__main__":
    app.run(debug=True)
