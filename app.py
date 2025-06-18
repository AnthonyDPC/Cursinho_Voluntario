from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, IntegerField, SelectField, TextAreaField, DateField, FloatField, PasswordField, FileField, HiddenField, TimeField
from wtforms.validators import DataRequired, Email, NumberRange, Length, Optional, URL
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, time
import os
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'sua_chave_secreta_muito_forte_aqui'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///escola.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Configurações para upload de arquivos
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static/uploads')
app.config['ALLOWED_EXTENSIONS'] = {'pdf', 'doc', 'docx', 'ppt', 'pptx', 'xls', 'xlsx'}
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5MB

# Criar pasta de uploads se não existir
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)

# Decorator para verificar login
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Decorator para verificar se é admin
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('user_tipo') != 'admin':
            flash('Acesso negado! Apenas administradores podem acessar esta área.', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# Modelo para usuários (admins e secretaria)
class Usuario(db.Model):
    __tablename__ = 'usuario'
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    senha_hash = db.Column(db.String(255), nullable=False)
    tipo = db.Column(db.String(20), nullable=False, default='admin')  # admin, secretaria
    ativo = db.Column(db.Boolean, default=True)
    criado_em = db.Column(db.DateTime, default=datetime.utcnow)
    
    def set_password(self, password):
        self.senha_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.senha_hash, password)
    
    def __repr__(self):
        return f'<Usuario {self.nome}>'

# Modelos do Banco de Dados (atualizados com campos de login)
class Aluno(db.Model):
    __tablename__ = 'aluno'
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    ra = db.Column(db.String(20), nullable=False, unique=True)
    data_nascimento = db.Column(db.Date)
    cpf = db.Column(db.String(14), nullable=False, unique=True)
    rg = db.Column(db.String(20))
    endereco = db.Column(db.String(255))
    bairro = db.Column(db.String(100))
    cidade = db.Column(db.String(100))
    email = db.Column(db.String(120), unique=True, nullable=False)
    telefone = db.Column(db.String(20))
    status = db.Column(db.Integer, default=1)
    senha_hash = db.Column(db.String(255), nullable=True)
    turma_id = db.Column(db.Integer, db.ForeignKey('turma.id'))
    notas = db.relationship('Nota', backref='aluno', lazy=True)
    turma = db.relationship('Turma', backref='aluno', lazy=True)

    def set_password(self, password):
        if password:
            from werkzeug.security import generate_password_hash
            self.senha_hash = generate_password_hash(password)

    def check_password(self, password):
        if self.senha_hash:
            from werkzeug.security import check_password_hash
            return check_password_hash(self.senha_hash, password)
        return False

    def __repr__(self):
        return f'<Aluno {self.nome}>'
    
class Professor(db.Model):
    __tablename__ = 'professor'
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    cpf = db.Column(db.String(14), nullable=False, unique=True)
    rg = db.Column(db.String(20))
    endereco = db.Column(db.String(255))
    bairro = db.Column(db.String(100))
    cidade = db.Column(db.String(100))
    email = db.Column(db.String(120), unique=True, nullable=False)
    telefone = db.Column(db.String(20))
    status = db.Column(db.Integer, default=1)
    senha_hash = db.Column(db.String(255), nullable=True)  # Novo campo
    especialidade = db.Column(db.String(100))
    ativo = db.Column(db.Boolean, default=True)  # Novo campo
    disciplinas_ministradas = db.relationship('Disciplina', back_populates='professor', lazy=True)
    
    def set_password(self, password):
        if password:
            self.senha_hash = generate_password_hash(password)
    
    def check_password(self, password):
        if self.senha_hash:
            return check_password_hash(self.senha_hash, password)
        return False
    
    def __repr__(self):
        return f'<Professor {self.nome}>'
    
class Curso(db.Model):
    __tablename__ = 'curso'
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    periodo = db.Column(db.String(50), nullable=False)  # Matutino, Vespertino, Noturno
    carga_horaria = db.Column(db.Integer, nullable=False)
    modalidade = db.Column(db.String(50), nullable=False)  # Presencial, Online, Híbrido
    status = db.Column(db.Integer, default=1)  # 1-Ativo, 0-Inativo

    def __repr__(self):
        return f'<Curso {self.nome}>'

class Disciplina(db.Model):
    __tablename__ = 'disciplina'
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    codigo = db.Column(db.String(20), unique=True, nullable=False)
    carga_horaria = db.Column(db.Integer)
    descricao = db.Column(db.Text)
    # ✨ NOVO CAMPO
    categoria = db.Column(db.String(50), default='geral') # ex: exatas, humanas, biologicas, geral
    professor_id = db.Column(db.Integer, db.ForeignKey('professor.id'))
    turma_id = db.Column(db.Integer, db.ForeignKey('turma.id'))
    
    # Relacionamentos
    professor = db.relationship('Professor', backref='minhas_disciplinas')
    turma = db.relationship('Turma', backref='disciplinas_vinculadas')
    notas = db.relationship('Nota', back_populates='disciplina', cascade="all, delete-orphan")
    faltas = db.relationship('Falta', back_populates='disciplina_rel', cascade="all, delete-orphan")
    
    def __repr__(self):
        return f'<Disciplina {self.nome}>'

class Material(db.Model):
    __tablename__ = 'material'
    id = db.Column(db.Integer, primary_key=True)
    titulo = db.Column(db.String(100), nullable=False)
    descricao = db.Column(db.Text)
    tipo = db.Column(db.String(20))  # 'arquivo', 'link', 'texto'
    caminho_arquivo = db.Column(db.String(255))
    url = db.Column(db.String(255))
    data_publicacao = db.Column(db.DateTime, default=datetime.utcnow)
    disciplina_id = db.Column(db.Integer, db.ForeignKey('disciplina.id'), nullable=False)
    professor_id = db.Column(db.Integer, db.ForeignKey('professor.id'), nullable=False)
    
    disciplina = db.relationship('Disciplina', backref='materiais')
    professor = db.relationship('Professor', backref='materiais')

    def __repr__(self):
        return f'<Material {self.titulo}>'
    
class Turma(db.Model):
    __tablename__ = 'turma'
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(50), nullable=False)
    curso_id = db.Column(db.Integer, db.ForeignKey('curso.id'), nullable=False)
    local = db.Column(db.String(100))
    periodo = db.Column(db.String(20))  # Matutino, Vespertino, Noturno
    ano = db.Column(db.Integer, nullable=False)
    semestre = db.Column(db.Integer, nullable=False)  # 1 ou 2
    status = db.Column(db.Integer, default=1)  # 1-Ativo, 0-Inativo
    
    curso = db.relationship('Curso', backref='turmas_vinculadas')
    alunos = db.relationship('Aluno', backref='turma_atual')
    disciplinas = db.relationship('Disciplina', backref='turma_associada')
    
    def __repr__(self):
        return f'<Turma {self.nome}>'

class Nota(db.Model):
    __tablename__ = 'nota'
    id = db.Column(db.Integer, primary_key=True)
    valor = db.Column(db.Float, nullable=False)
    tipo = db.Column(db.String(20), nullable=False)  # 'P1', 'P2', 'Trabalho', etc.
    data = db.Column(db.Date, default=datetime.utcnow)
    aluno_id = db.Column(db.Integer, db.ForeignKey('aluno.id'), nullable=False)
    disciplina_id = db.Column(db.Integer, db.ForeignKey('disciplina.id'), nullable=False)
    
    # Adicione este relacionamento
    disciplina = db.relationship('Disciplina', back_populates='notas')
    
    def __repr__(self):
        return f'<Nota {self.valor}>'

class Aula(db.Model):
    __tablename__ = 'aula'
    id = db.Column(db.Integer, primary_key=True)
    data = db.Column(db.Date, nullable=False, default=datetime.utcnow)
    conteudo = db.Column(db.Text, nullable=False)
    observacoes = db.Column(db.Text)
    disciplina_id = db.Column(db.Integer, db.ForeignKey('disciplina.id'), nullable=False)
    professor_id = db.Column(db.Integer, db.ForeignKey('professor.id'), nullable=False)
    criado_em = db.Column(db.DateTime, default=datetime.utcnow)
    hora_inicio = db.Column(db.Time)
    hora_fim = db.Column(db.Time)

    # Relacionamentos
    disciplina = db.relationship('Disciplina', backref='aulas')
    professor = db.relationship('Professor', backref='aulas_ministradas')

    def __repr__(self):
        return f'<Aula {self.data} - {self.disciplina.nome}>'
    
class Falta(db.Model):
    __tablename__ = 'falta'
    id = db.Column(db.Integer, primary_key=True)
    data = db.Column(db.Date, default=datetime.utcnow, nullable=False)
    motivo = db.Column(db.String(255))
    aluno_id = db.Column(db.Integer, db.ForeignKey('aluno.id'), nullable=False)
    disciplina_id = db.Column(db.Integer, db.ForeignKey('disciplina.id'), nullable=False)
    
    # Relacionamentos
    aluno = db.relationship('Aluno', backref='minhas_faltas')
    disciplina_rel = db.relationship('Disciplina', back_populates='faltas')
    
    def __repr__(self):
        return f'<Falta {self.data} - Aluno {self.aluno_id}>'

# Formulários
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    senha = PasswordField('Senha', validators=[DataRequired()])
    tipo_usuario = SelectField('Tipo de Usuário', 
                              choices=[('admin', 'Administrador/Secretaria'), 
                                     ('professor', 'Professor'), 
                                     ('aluno', 'Aluno')],
                              default='admin')

class UsuarioForm(FlaskForm):
    nome = StringField('Nome', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    senha = PasswordField('Senha', validators=[DataRequired(), Length(min=6)])
    tipo = SelectField('Tipo', choices=[('admin', 'Administrador'), ('secretaria', 'Secretaria')])

class AlunoForm(FlaskForm):
    id = IntegerField('ID')
    nome = StringField('Nome', validators=[DataRequired()])
    data_nascimento = DateField('Data de Nascimento', format='%Y-%m-%d')
    cpf = StringField('CPF', validators=[DataRequired()])
    rg = StringField('RG')
    endereco = TextAreaField('Endereço')
    bairro = StringField('Bairro')
    cidade = StringField('Cidade')
    email = StringField('Email', validators=[DataRequired(), Email()])
    status = IntegerField('Status', default=1)
    senha = PasswordField('Senha', validators=[Length(min=0, max=100)], render_kw={"placeholder": "Deixe em branco se não quiser login"})
    turma_id = SelectField('Turma', coerce=int)
    telefone = StringField('Telefone')

class ProfessorForm(FlaskForm):
    nome = StringField('Nome', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    senha = PasswordField('Senha', validators=[Length(min=0, max=100)], render_kw={"placeholder": "Deixe em branco se não quiser login"})
    telefone = StringField('Telefone')
    especialidade = StringField('Especialidade')

class CursoForm(FlaskForm):
    nome = StringField('Nome do Curso', validators=[DataRequired(), Length(max=100)])
    periodo = SelectField('Período', choices=[
        ('Matutino', 'Matutino'),
        ('Vespertino', 'Vespertino'), 
        ('Noturno', 'Noturno')
    ], validators=[DataRequired()])
    carga_horaria = IntegerField('Carga Horária (horas)', validators=[DataRequired(), NumberRange(min=1)])
    modalidade = SelectField('Modalidade', choices=[
        ('Presencial', 'Presencial'),
        ('Online', 'Online'),
        ('Híbrido', 'Híbrido')
    ], validators=[DataRequired()])
    status = SelectField('Status', choices=[
        (1, 'Ativo'),
        (0, 'Inativo')
    ], coerce=int, validators=[DataRequired()])

class DisciplinaForm(FlaskForm):
    nome = StringField('Nome', validators=[DataRequired()])
    codigo = StringField('Código', validators=[DataRequired()])
    carga_horaria = IntegerField('Carga Horária')
    descricao = TextAreaField('Descrição')
    # ✨ CAMPO ATUALIZADO
    categoria = SelectField('Categoria', choices=[
        ('exatas', 'Exatas'),
        ('humanas', 'Humanas'),
        ('biologicas', 'Biológicas'),
        ('linguagens', 'Linguagens'),
        ('geral', 'Geral')
    ], validators=[DataRequired()])
    professor_id = SelectField('Professor', coerce=int, validators=[Optional()])
    turma_id = SelectField('Turma', coerce=int, validators=[Optional()])


class MaterialForm(FlaskForm):
    titulo = StringField('Título', validators=[DataRequired()])
    descricao = TextAreaField('Descrição')
    tipo = SelectField('Tipo', choices=[
        ('arquivo', 'Arquivo'), 
        ('link', 'Link'), 
        ('texto', 'Texto')
    ], validators=[DataRequired()])
    arquivo = FileField('Arquivo')
    url = StringField('URL', validators=[Optional(), URL()])
    disciplina_id = SelectField('Disciplina', coerce=int, validators=[DataRequired()])

class TurmaForm(FlaskForm):
    nome = StringField('Nome da Turma', validators=[DataRequired(), Length(max=50)])
    curso_id = SelectField('Curso', coerce=int, validators=[DataRequired()])
    local = StringField('Local', validators=[Length(max=100)])
    periodo = SelectField('Período', choices=[
        ('Matutino', 'Matutino'),
        ('Vespertino', 'Vespertino'),
        ('Noturno', 'Noturno')
    ], validators=[DataRequired()])
    ano = IntegerField('Ano', validators=[DataRequired(), NumberRange(min=2000, max=2100)])
    semestre = SelectField('Semestre', choices=[(1, '1º Semestre'), (2, '2º Semestre')], 
                         coerce=int, validators=[DataRequired(), NumberRange(min=1, max=2)])
    status = SelectField('Status', choices=[(1, 'Ativo'), (0, 'Inativo')], 
                        coerce=int, validators=[DataRequired()])

class NotaForm(FlaskForm):
    valor = FloatField('Nota', validators=[DataRequired(), NumberRange(min=0, max=10)])
    tipo = SelectField('Tipo', choices=[('P1', 'Prova 1'), ('P2', 'Prova 2'), ('Trabalho', 'Trabalho'), ('Participacao', 'Participação')])
    aluno_id = SelectField('Aluno', coerce=int)
    disciplina_id = SelectField('Disciplina', coerce=int)

# Adicione este novo formulário junto com os outros
class AulaForm(FlaskForm):
    disciplina_id = SelectField('Disciplina', coerce=int, validators=[DataRequired()])
    data = DateField('Data da Aula', validators=[DataRequired()], default=datetime.today, format='%Y-%m-%d')
    hora_inicio = TimeField('Horário de Início', validators=[DataRequired()], format='%H:%M')
    hora_fim = TimeField('Horário de Fim', validators=[DataRequired()], format='%H:%M')
    conteudo = TextAreaField('Conteúdo Ministrado', validators=[DataRequired()], render_kw={"rows": 6, "placeholder": "Descreva o conteúdo principal abordado na aula..."})
    observacoes = TextAreaField('Observações (opcional)', render_kw={"rows": 3, "placeholder": "Anote informações adicionais, como tarefas passadas, comportamento da turma, etc."}) 
   
# Em app.py, encontre o FaltaForm e altere o campo 'data'

class FaltaForm(FlaskForm):
    # O campo 'data' foi renomeado e alterado para SelectField
    data_aula = SelectField('Data da Aula', validators=[DataRequired()], choices=[])
    motivo = StringField('Motivo (opcional)', validators=[Length(max=255)])
    aluno_id = SelectField('Aluno', coerce=int, validators=[DataRequired()]) # Alterado de HiddenField para SelectField
    disciplina_id = SelectField('Disciplina', coerce=int, validators=[DataRequired()])

# Função para inicializar o banco de dados
def init_db():
    """Inicializa o banco de dados criando todas as tabelas"""
    try:
        db.create_all()
        print("Banco de dados criado com sucesso!")
        return True
    except Exception as e:
        print(f"Erro ao criar banco de dados: {e}")
        return False

# Função para autenticação unificada
def autenticar_usuario(email, senha, tipo_usuario):
    """Autentica usuário baseado no tipo (admin, professor, aluno)"""
    try:
        if tipo_usuario == 'admin':
            usuario = Usuario.query.filter_by(email=email, ativo=True).first()
            if usuario and usuario.check_password(senha):
                return {
                    'id': usuario.id,
                    'nome': usuario.nome,
                    'tipo': usuario.tipo,
                    'email': usuario.email
                }
        elif tipo_usuario == 'professor':
            professor = Professor.query.filter_by(email=email, status=1).first()
            if professor and professor.check_password(senha):
                return {
                    'id': professor.id,
                    'nome': professor.nome,
                    'tipo': 'professor',
                    'email': professor.email
                }
        elif tipo_usuario == 'aluno':
            aluno = Aluno.query.filter_by(email=email, status=1).first()
            if aluno and aluno.check_password(senha):
                return {
                    'id': aluno.id,
                    'nome': aluno.nome,
                    'tipo': 'aluno',
                    'email': aluno.email,
                    'turma_id': aluno.turma_id
                }
        return None
    except Exception as e:
        print(f"Erro na autenticação: {e}")
        return None

# Rotas de autenticação
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        try:
            usuario_data = autenticar_usuario(
                form.email.data, 
                form.senha.data, 
                form.tipo_usuario.data
            )
            
            if usuario_data:
                session['user_id'] = usuario_data['id']
                session['user_nome'] = usuario_data['nome']
                session['user_tipo'] = usuario_data['tipo']
                session['user_email'] = usuario_data['email']
                
                # Para alunos, salvar também a turma
                if usuario_data['tipo'] == 'aluno':
                    session['turma_id'] = usuario_data.get('turma_id')
                
                flash(f'Bem-vindo, {usuario_data["nome"]}!', 'success')
                return redirect(url_for('index'))
            else:
                flash('Email, senha ou tipo de usuário incorretos!', 'error')
        except Exception as e:
            print(f"Erro no login: {e}")
            flash('Erro interno do sistema. Tente novamente.', 'error')
    
    return render_template('auth/login.html', form=form)

@app.route('/logout')
def logout():
    session.clear()
    flash('Logout realizado com sucesso!', 'success')
    return redirect(url_for('login'))

@app.route('/criar-admin', methods=['GET', 'POST'])
def criar_admin():
    # Verificar se já existe um admin
    if Usuario.query.filter_by(tipo='admin').first():
        flash('Já existe um administrador no sistema!', 'error')
        return redirect(url_for('login'))
    
    form = UsuarioForm()
    if form.validate_on_submit():
        usuario = Usuario(
            nome=form.nome.data,
            email=form.email.data,
            tipo='admin'
        )
        usuario.set_password(form.senha.data)
        db.session.add(usuario)
        db.session.commit()
        flash('Administrador criado com sucesso! Faça login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('auth/criar_admin.html', form=form)

# Rotas principais (com diferentes níveis de acesso)
@app.route('/')
@login_required
def index():
    user_tipo = session.get('user_tipo')
    
    # Dashboard específico para cada tipo de usuário
    if user_tipo == 'aluno':
        return redirect(url_for('dashboard_aluno'))
    elif user_tipo == 'professor':
        return redirect(url_for('dashboard_professor'))
    else:
        return redirect(url_for('listar_alunos'))

@app.route('/dashboard-aluno')
@login_required
def dashboard_aluno():
    if session.get('user_tipo') != 'aluno':
        flash('Acesso negado!', 'error')
        return redirect(url_for('index'))

    aluno_id = session.get('user_id')
    aluno = Aluno.query.get(aluno_id)
    notas = Nota.query.filter_by(aluno_id=aluno_id).all()
    faltas = Falta.query.filter_by(aluno_id=aluno_id).all()

    # Obter disciplinas únicas do aluno
    disciplinas_ids = {nota.disciplina_id for nota in notas}
    disciplinas = Disciplina.query.filter(Disciplina.id.in_(disciplinas_ids)).all()

    # Agrupar médias por disciplina
    media_por_disciplina = {}
    for nota in notas:
        nome_disc = nota.disciplina.nome
        if nome_disc not in media_por_disciplina:
            media_por_disciplina[nome_disc] = []
        media_por_disciplina[nome_disc].append(nota.valor)
    medias = {disc: round(sum(valores)/len(valores), 2) for disc, valores in media_por_disciplina.items()}

    # Contar faltas por disciplina
    faltas_por_disciplina = {}
    for falta in faltas:
        nome_disc = falta.disciplina_rel.nome
        faltas_por_disciplina[nome_disc] = faltas_por_disciplina.get(nome_disc, 0) + 1

    return render_template(
        'dashboard/aluno.html',
        aluno=aluno,
        notas=notas,
        faltas=faltas,
        disciplinas=disciplinas,
        medias=medias,
        turma=aluno.turma,
        faltas_por_disciplina=faltas_por_disciplina
    )

@app.route('/dashboard-professor')
@login_required
def dashboard_professor():
    if session.get('user_tipo') != 'professor':
        flash('Acesso negado!', 'error')
        return redirect(url_for('index'))

    professor_id = session.get('user_id')
    professor = Professor.query.get(professor_id)
    disciplinas = Disciplina.query.filter_by(professor_id=professor_id).all()

    alunos_por_disciplina = {}
    faltas_por_disciplina = {}

    for disciplina in disciplinas:
        # Alunos que têm notas ou faltas nessa disciplina
        alunos_ids = set(nota.aluno_id for nota in disciplina.notas)
        alunos = Aluno.query.filter(Aluno.id.in_(alunos_ids)).all()
        alunos_por_disciplina[disciplina.nome] = alunos

        faltas = Falta.query.filter_by(disciplina_id=disciplina.id).all()
        faltas_por_disciplina[disciplina.nome] = faltas

    return render_template(
        'dashboard/professor.html',
        professor=professor,
        disciplinas=disciplinas,
        alunos_por_disciplina=alunos_por_disciplina,
        faltas_por_disciplina=faltas_por_disciplina,
        alunos_qtd={d.nome: len(alunos_por_disciplina[d.nome]) for d in disciplinas},
        faltas_qtd={d.nome: len(faltas_por_disciplina[d.nome]) for d in disciplinas}
    )

# Rotas para Usuários (apenas admin)
@app.route('/usuarios')
@admin_required
def listar_usuarios():
    usuarios = Usuario.query.all()
    return render_template('usuarios/listar.html', usuarios=usuarios)

@app.route('/usuarios/novo', methods=['GET', 'POST'])
@admin_required
def novo_usuario():
    form = UsuarioForm()
    if form.validate_on_submit():
        try:
            usuario = Usuario(
                nome=form.nome.data,
                email=form.email.data,
                tipo=form.tipo.data
            )
            usuario.set_password(form.senha.data)
            db.session.add(usuario)
            db.session.commit()
            flash('Usuário cadastrado com sucesso!', 'success')
            return redirect(url_for('listar_usuarios'))
        except Exception as e:
            db.session.rollback()
            flash(f'Erro ao cadastrar usuário: {str(e)}', 'error')
    
    return render_template('usuarios/form.html', form=form, titulo='Novo Usuário')

@app.route('/usuarios/<int:id>/deletar', methods=['POST'])
@admin_required
def deletar_usuario(id):
    if id == session.get('user_id'):
        flash('Você não pode excluir seu próprio usuário!', 'error')
        return redirect(url_for('listar_usuarios'))
    
    try:
        usuario = Usuario.query.get_or_404(id)
        db.session.delete(usuario)
        db.session.commit()
        flash('Usuário excluído com sucesso!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Erro ao excluir usuário: {str(e)}', 'error')
    
    return redirect(url_for('listar_usuarios'))

# Rotas para Alunos (protegidas)
@app.route('/alunos')
@login_required
def listar_alunos():
    # Professores só podem ver alunos de suas disciplinas
    if session.get('user_tipo') == 'professor':
        professor_id = session.get('user_id')
        disciplinas = Disciplina.query.filter_by(professor_id=professor_id).all()
        alunos_ids = set()
        for disciplina in disciplinas:
            for nota in disciplina.notas:
                alunos_ids.add(nota.aluno_id)
        alunos = Aluno.query.filter(Aluno.id.in_(alunos_ids)).all() if alunos_ids else []
    else:
        alunos = Aluno.query.all()
    
    return render_template('alunos/listar.html', alunos=alunos)

@app.route('/alunos/novo', methods=['GET', 'POST'])
@login_required
def novo_aluno():
    if session.get('user_tipo') == 'aluno':
        flash('Acesso negado!', 'error')
        return redirect(url_for('index'))
    
    form = AlunoForm()
    form.turma_id.choices = [(t.id, t.nome) for t in Turma.query.all()]
    form.turma_id.choices.insert(0, (0, 'Selecione uma turma'))

    if form.validate_on_submit():
        try:
            novo_ra = 0
            ultimo = Aluno.query.order_by(Aluno.ra.desc()).first()
            if ultimo and ultimo.ra.isdigit():
                novo_ra = str(int(ultimo.ra) + 1)
            novo_ra = "1000"
            
            aluno = Aluno(
                nome=form.nome.data,
                ra=novo_ra,
                cpf=form.cpf.data,
                rg=form.rg.data,
                data_nascimento=form.data_nascimento.data,
                endereco=form.endereco.data,
                bairro=form.bairro.data,
                cidade=form.cidade.data,
                telefone=form.telefone.data,
                email=form.email.data,
                status=form.status.data or 1,
                turma_id=form.turma_id.data if form.turma_id.data != 0 else None
            )

            if form.senha.data and len(form.senha.data.strip()) >= 6:
                aluno.set_password(form.senha.data)
                flash(f'Aluno cadastrado com sucesso! Login habilitado com email: {aluno.email}', 'success')
            else:
                flash('Aluno cadastrado com sucesso! Login não habilitado.', 'success')

            db.session.add(aluno)
            db.session.commit()
            return redirect(url_for('listar_alunos'))
        except Exception as e:
            import traceback
            traceback.print_exc()
            db.session.rollback()
            flash(f'Erro ao cadastrar aluno: {str(e)}', 'error')

    if request.method == 'POST':
        print("ERROS DE FORMULÁRIO:", form.errors)

    return render_template('alunos/form.html', form=form, titulo='Novo Aluno')

# Modificar a rota de editar aluno
@app.route('/alunos/<int:id>/editar', methods=['GET', 'POST'])
@login_required
def editar_aluno(id):
    if session.get('user_tipo') == 'aluno' and session.get('user_id') != id:
        flash('Você só pode editar seu próprio perfil!', 'error')
        return redirect(url_for('index'))
    
    aluno = Aluno.query.get_or_404(id)
    form = AlunoForm(obj=aluno)
    form.turma_id.choices = [(t.id, t.nome) for t in Turma.query.all()]
    form.turma_id.choices.insert(0, (0, 'Selecione uma turma'))
    
    # Marcar se já tem senha para o JavaScript
    if aluno.senha_hash:
        form.senha.render_kw = {**form.senha.render_kw, 'data-has-password': 'true'}
    
    if form.validate_on_submit():
        try:
            aluno.nome = form.nome.data
            aluno.email = form.email.data
            aluno.telefone = form.telefone.data
            aluno.data_nascimento = form.data_nascimento.data
            aluno.endereco = form.endereco.data
            
            # Só admin/secretaria pode alterar turma
            if session.get('user_tipo') in ['admin', 'secretaria']:
                aluno.turma_id = form.turma_id.data if form.turma_id.data != 0 else None
            
            # Atualizar senha se fornecida
            if form.senha.data and len(form.senha.data.strip()) >= 6:
                aluno.set_password(form.senha.data)
                flash('Aluno atualizado com sucesso! Senha alterada.', 'success')
            elif not form.senha.data and not aluno.senha_hash:
                flash('Aluno atualizado com sucesso! Login não habilitado.', 'success')
            else:
                flash('Aluno atualizado com sucesso!', 'success')
            
            db.session.commit()
            return redirect(url_for('listar_alunos'))
        except Exception as e:
            db.session.rollback()
            flash(f'Erro ao atualizar aluno: {str(e)}', 'error')
    
    return render_template('alunos/form.html', form=form, titulo='Editar Aluno', aluno=aluno)

@app.route('/alunos/<int:id>/deletar', methods=['POST'])
@login_required
def deletar_aluno(id):
    if session.get('user_tipo') not in ['admin', 'secretaria']:
        flash('Acesso negado!', 'error')
        return redirect(url_for('index'))
    
    try:
        aluno = Aluno.query.get_or_404(id)
        db.session.delete(aluno)
        db.session.commit()
        flash('Aluno excluído com sucesso!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Erro ao excluir aluno: {str(e)}', 'error')
    
    return redirect(url_for('listar_alunos'))

# Rotas para Professores (protegidas)
@app.route('/professores')
@login_required
def listar_professores():
    if session.get('user_tipo') == 'professor':
        # Professor só vê seu próprio perfil
        professor_id = session.get('user_id')
        professores = [Professor.query.get(professor_id)]
    else:
        professores = Professor.query.all()
    
    return render_template('professores/listar.html', professores=professores)

# Modificar a rota de novo professor
@app.route('/professores/novo', methods=['GET', 'POST'])
@login_required
def novo_professor():
    if session.get('user_tipo') not in ['admin', 'secretaria']:
        flash('Acesso negado!', 'error')
        return redirect(url_for('index'))
    
    form = ProfessorForm()
    
    if form.validate_on_submit():
        try:
            # Verificar se o login está habilitado e senhas coincidem
            habilitar_login = 'habilitar_login' in request.form
            senha = form.senha.data if habilitar_login else None
            
            if habilitar_login and (not senha or len(senha.strip()) < 6):
                flash('A senha deve ter pelo menos 6 caracteres quando o login está habilitado!', 'error')
                return render_template('professores/form.html', form=form, titulo='Novo Professor')
            
            professor = Professor(
                nome=form.nome.data,
                email=form.email.data,
                telefone=form.telefone.data,
                especialidade=form.especialidade.data,
                cpf=request.form.get('cpf'),
                rg=request.form.get('rg'),
                endereco=request.form.get('endereco'),
                bairro=request.form.get('bairro'),
                cidade=request.form.get('cidade'),
                status=1
            )
            
            # Definir senha se fornecida
            if habilitar_login and senha:
                professor.set_password(senha)
                flash(f'Professor cadastrado com sucesso! Login habilitado com email: {professor.email}', 'success')
            else:
                flash('Professor cadastrado com sucesso! Login não habilitado.', 'success')
            
            db.session.add(professor)
            db.session.commit()
            return redirect(url_for('listar_professores'))
        except Exception as e:
            db.session.rollback()
            flash(f'Erro ao cadastrar professor: {str(e)}', 'error')
    
    return render_template('professores/form.html', form=form, titulo='Novo Professor')

@app.route('/professores/<int:id>/editar', methods=['GET', 'POST'])
@login_required
def editar_professor(id):
    if session.get('user_tipo') == 'professor' and session.get('user_id') != id:
        flash('Você só pode editar seu próprio perfil!', 'error')
        return redirect(url_for('index'))
    
    professor = Professor.query.get_or_404(id)
    form = ProfessorForm(obj=professor)
    
    # Marcar se já tem senha para o JavaScript
    if professor.senha_hash:
        form.senha.render_kw = {**form.senha.render_kw, 'data-has-password': 'true'}
    
    if form.validate_on_submit():
        try:
            professor.nome = form.nome.data
            professor.email = form.email.data
            professor.telefone = form.telefone.data
            professor.especialidade = form.especialidade.data
            
            # Atualizar senha se fornecida
            if form.senha.data and len(form.senha.data.strip()) >= 6:
                professor.set_password(form.senha.data)
                flash('Professor atualizado com sucesso! Senha alterada.', 'success')
            elif not form.senha.data and not professor.senha_hash:
                flash('Professor atualizado com sucesso! Login não habilitado.', 'success')
            else:
                flash('Professor atualizado com sucesso!', 'success')
            
            db.session.commit()
            return redirect(url_for('listar_professores'))
        except Exception as e:
            db.session.rollback()
            flash(f'Erro ao atualizar professor: {str(e)}', 'error')
    
    return render_template('professores/form.html', form=form, titulo='Editar Professor', professor=professor)

@app.route('/professores/<int:id>/deletar', methods=['POST'])
@login_required
def deletar_professor(id):
    if session.get('user_tipo') not in ['admin', 'secretaria']:
        flash('Acesso negado!', 'error')
        return redirect(url_for('listar_professores'))

    professor = Professor.query.get_or_404(id)
    try:
        # Check if the professor is linked to any disciplines
        if professor.minhas_disciplinas:
             flash(f'Erro: Não é possível excluir o professor "{professor.nome}" pois ele está vinculado a {len(professor.minhas_disciplinas)} disciplina(s).', 'error')
             return redirect(url_for('listar_professores'))

        db.session.delete(professor)
        db.session.commit()
        flash(f'Professor "{professor.nome}" excluído com sucesso!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Erro ao excluir professor: {str(e)}', 'error')
            
    return redirect(url_for('listar_professores'))

# Listar cursos
@app.route('/cursos')
@admin_required
def listar_cursos():
    cursos = Curso.query.order_by(Curso.nome).all()
    return render_template('cursos/listar.html', cursos=cursos)

# Adicionar curso
@app.route('/cursos/novo', methods=['GET', 'POST'])
@admin_required
def novo_curso():
    form = CursoForm()
    
    if form.validate_on_submit():
        try:
            curso = Curso(
                nome=form.nome.data,
                periodo=form.periodo.data,
                carga_horaria=form.carga_horaria.data,
                modalidade=form.modalidade.data,
                status=form.status.data
            )
            db.session.add(curso)
            db.session.commit()
            flash('Curso cadastrado com sucesso!', 'success')
            return redirect(url_for('listar_cursos'))
        except Exception as e:
            db.session.rollback()
            flash(f'Erro ao cadastrar curso: {str(e)}', 'error')
    
    return render_template('cursos/form.html', form=form, titulo='Novo Curso')

# Editar curso
@app.route('/cursos/<int:id>/editar', methods=['GET', 'POST'])
@admin_required
def editar_curso(id):
    curso = Curso.query.get_or_404(id)
    form = CursoForm(obj=curso)
    
    if form.validate_on_submit():
        try:
            curso.nome = form.nome.data
            curso.periodo = form.periodo.data
            curso.carga_horaria = form.carga_horaria.data
            curso.modalidade = form.modalidade.data
            curso.status = form.status.data
            
            db.session.commit()
            flash('Curso atualizado com sucesso!', 'success')
            return redirect(url_for('listar_cursos'))
        except Exception as e:
            db.session.rollback()
            flash(f'Erro ao atualizar curso: {str(e)}', 'error')
    
    return render_template('cursos/form.html', form=form, titulo='Editar Curso')

# Deletar curso
@app.route('/cursos/<int:id>/deletar', methods=['POST'])
@admin_required
def deletar_curso(id):
    curso = Curso.query.get_or_404(id)
    
    try:
        db.session.delete(curso)
        db.session.commit()
        flash('Curso excluído com sucesso!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Erro ao excluir curso: {str(e)}', 'error')
    
    return redirect(url_for('listar_cursos'))

# Função para criar cursos iniciais
def criar_cursos_iniciais():
    cursos_iniciais = [
        {'nome': 'Ensino médio', 'periodo': 'Matutino', 'carga_horaria': 2000, 'modalidade': 'Presencial', 'status': 1},
        {'nome': 'Pré vestibular', 'periodo': 'Noturno', 'carga_horaria': 800, 'modalidade': 'Presencial', 'status': 1},
        {'nome': 'Pré vestibulinho', 'periodo': 'Vespertino', 'carga_horaria': 600, 'modalidade': 'Presencial', 'status': 1},
        {'nome': 'Empreendedorismo', 'periodo': 'Noturno', 'carga_horaria': 120, 'modalidade': 'Híbrido', 'status': 1}
    ]
    
    with app.app_context():
        for curso_data in cursos_iniciais:
            if not Curso.query.filter_by(nome=curso_data['nome']).first():
                curso = Curso(**curso_data)
                db.session.add(curso)
        db.session.commit()

# Rotas para Disciplinas (protegidas)
@app.route('/disciplinas')
@login_required
def listar_disciplinas():
    # Acesso baseado no tipo de usuário
    if session.get('user_tipo') == 'professor':
        professor_id = session.get('user_id')
        disciplinas = Disciplina.query.filter_by(professor_id=professor_id).all()
    else: # Admin e Secretaria veem todas
        disciplinas = Disciplina.query.all()
    
    # ✨ CÁLCULO DAS ESTATÍSTICAS
    total_disciplinas = len(disciplinas)
    if total_disciplinas > 0:
        disciplinas_com_professor = sum(1 for d in disciplinas if d.professor_id)
        total_horas = sum(d.carga_horaria or 0 for d in disciplinas)
        media_horas = round(total_horas / total_disciplinas)
    else:
        disciplinas_com_professor = 0
        total_horas = 0
        media_horas = 0

    return render_template(
        'disciplinas/listar.html', 
        disciplinas=disciplinas,
        total_disciplinas=total_disciplinas,
        disciplinas_com_professor=disciplinas_com_professor,
        total_horas=total_horas,
        media_horas=media_horas
    )

@app.route('/disciplinas/nova', methods=['GET', 'POST'])
@login_required
def nova_disciplina():
    if session.get('user_tipo') not in ['admin', 'secretaria']:
        flash('Acesso negado!', 'error')
        return redirect(url_for('listar_disciplinas'))
    
    form = DisciplinaForm()
    # Populando SelectFields
    form.professor_id.choices = [(p.id, p.nome) for p in Professor.query.order_by(Professor.nome).all()]
    form.professor_id.choices.insert(0, (0, 'Selecione um Professor'))
    form.turma_id.choices = [(t.id, f"{t.nome} - {t.curso.nome}") for t in Turma.query.order_by(Turma.nome).all()]
    form.turma_id.choices.insert(0, (0, 'Selecione uma Turma'))
    
    if form.validate_on_submit():
        try:
            disciplina = Disciplina(
                nome=form.nome.data,
                codigo=form.codigo.data,
                carga_horaria=form.carga_horaria.data,
                descricao=form.descricao.data,
                categoria=form.categoria.data, # ✨
                professor_id=form.professor_id.data if form.professor_id.data != 0 else None,
                turma_id=form.turma_id.data if form.turma_id.data != 0 else None
            )
            db.session.add(disciplina)
            db.session.commit()
            flash('Disciplina cadastrada com sucesso!', 'success')
            return redirect(url_for('listar_disciplinas'))
        except Exception as e:
            db.session.rollback()
            flash(f'Erro ao cadastrar disciplina: {str(e)}', 'error')
    
    return render_template('disciplinas/form.html', form=form, titulo='Nova Disciplina')

@app.route('/disciplinas/<int:id>/editar', methods=['GET', 'POST'])
@login_required
def editar_disciplina(id):
    if session.get('user_tipo') not in ['admin', 'secretaria']:
        flash('Acesso negado!', 'error')
        return redirect(url_for('listar_disciplinas'))
        
    disciplina = Disciplina.query.get_or_404(id)
    form = DisciplinaForm(obj=disciplina)
    
    if request.method == 'GET':
        # Garante que o valor correto seja selecionado no carregamento
        form.professor_id.data = disciplina.professor_id
        form.turma_id.data = disciplina.turma_id
        form.categoria.data = disciplina.categoria

    # Populando SelectFields
    form.professor_id.choices = [(p.id, p.nome) for p in Professor.query.order_by(Professor.nome).all()]
    form.professor_id.choices.insert(0, (0, 'Selecione um Professor'))
    form.turma_id.choices = [(t.id, f"{t.nome} - {t.curso.nome}") for t in Turma.query.order_by(Turma.nome).all()]
    form.turma_id.choices.insert(0, (0, 'Selecione uma Turma'))

    if form.validate_on_submit():
        try:
            disciplina.nome = form.nome.data
            disciplina.codigo = form.codigo.data
            disciplina.carga_horaria = form.carga_horaria.data
            disciplina.descricao = form.descricao.data
            disciplina.categoria = form.categoria.data # ✨
            disciplina.professor_id = form.professor_id.data if form.professor_id.data != 0 else None
            disciplina.turma_id = form.turma_id.data if form.turma_id.data != 0 else None
            db.session.commit()
            flash('Disciplina atualizada com sucesso!', 'success')
            return redirect(url_for('listar_disciplinas'))
        except Exception as e:
            db.session.rollback()
            flash(f'Erro ao atualizar disciplina: {str(e)}', 'error')
            
    return render_template('disciplinas/form.html', form=form, titulo='Editar Disciplina', disciplina=disciplina)

@app.route('/disciplinas/<int:id>/deletar', methods=['POST'])
@login_required
def deletar_disciplina(id):
    if session.get('user_tipo') not in ['admin', 'secretaria']:
        flash('Acesso negado!', 'error')
        return redirect(url_for('listar_disciplinas'))

    disciplina = Disciplina.query.get_or_404(id)
    try:
        db.session.delete(disciplina)
        db.session.commit()
        flash(f'Disciplina "{disciplina.nome}" excluída com sucesso!', 'success')
    except Exception as e:
        db.session.rollback()
        # Tratamento para erro de chave estrangeira
        if "FOREIGN KEY constraint failed" in str(e):
            flash(f'Erro: Não é possível excluir a disciplina "{disciplina.nome}" pois ela está vinculada a notas, faltas ou materiais.', 'error')
        else:
            flash(f'Erro ao excluir disciplina: {str(e)}', 'error')
            
    return redirect(url_for('listar_disciplinas'))

@app.route('/disciplinas/<int:id>')
@login_required
def detalhes_disciplina(id):
    disciplina = Disciplina.query.get_or_404(id)
    return render_template('disciplinas/detalhes.html', disciplina=disciplina)

@app.route('/materiais')
@login_required
def listar_materiais():
    if session.get('user_tipo') == 'professor':
        materiais = Material.query.filter_by(professor_id=session.get('user_id')).all()
    else:
        flash('Acesso negado!', 'error')
        return redirect(url_for('index'))
    
    return render_template('materiais/listar.html', materiais=materiais)

@app.route('/materiais/novo', methods=['GET', 'POST'])
@login_required
def novo_material():
    if session.get('user_tipo') != 'professor':
        flash('Acesso negado!', 'error')
        return redirect(url_for('index'))
    
    form = MaterialForm()
    form.disciplina_id.choices = [(d.id, d.nome) for d in Disciplina.query.filter_by(professor_id=session.get('user_id')).all()]
    
    if form.validate_on_submit():
        try:
            material = Material(
                titulo=form.titulo.data,
                descricao=form.descricao.data,
                tipo=form.tipo.data,
                professor_id=session.get('user_id'),
                disciplina_id=form.disciplina_id.data
            )
            
            if form.tipo.data == 'arquivo' and form.arquivo.data:
                arquivo = form.arquivo.data
                filename = arquivo.filename
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                arquivo.save(filepath)
                material.caminho_arquivo = filename
            
            elif form.tipo.data == 'link':
                material.url = form.url.data
            
            db.session.add(material)
            db.session.commit()
            flash('Material adicionado com sucesso!', 'success')
            return redirect(url_for('listar_materiais'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Erro ao adicionar material: {str(e)}', 'error')
    
    return render_template('materiais/form.html', form=form, titulo='Novo Material')

@app.route('/materiais/<int:id>/deletar', methods=['POST'])
@login_required
def deletar_material(id):
    material = Material.query.get_or_404(id)
    
    if session.get('user_id') != material.professor_id and session.get('user_tipo') != 'admin':
        flash('Acesso negado!', 'error')
        return redirect(url_for('listar_materiais'))
    
    try:
        if material.tipo == 'arquivo' and material.caminho_arquivo:
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], material.caminho_arquivo)
            if os.path.exists(filepath):
                os.remove(filepath)
        
        db.session.delete(material)
        db.session.commit()
        flash('Material excluído com sucesso!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Erro ao excluir material: {str(e)}', 'error')
    
    return redirect(url_for('listar_materiais'))

@app.route('/materiais/aluno')
@login_required
def ver_materiais():
    if session.get('user_tipo') != 'aluno':
        flash('Acesso negado!', 'error')
        return redirect(url_for('index'))
    
    aluno = Aluno.query.get(session.get('user_id'))
    if not aluno or not aluno.turma_id:
        flash('Você não está matriculado em nenhuma turma!', 'error')
        return redirect(url_for('index'))
    
    # Obter disciplinas do aluno (através das notas)
    disciplinas_ids = {n.disciplina_id for n in aluno.notas}
    materiais = Material.query.filter(Material.disciplina_id.in_(disciplinas_ids)).all()
    
    return render_template('materiais/aluno.html', materiais=materiais)

# Rotas para Turmas (protegidas)
@app.route('/turmas')
@login_required
def listar_turmas():
    turmas = Turma.query.all()
    return render_template('turmas/listar.html', turmas=turmas)

@app.route('/turmas/nova', methods=['GET', 'POST'])
@login_required
def nova_turma():
    if session.get('user_tipo') not in ['admin', 'secretaria']:
        flash('Acesso negado!', 'error')
        return redirect(url_for('index'))
    
    form = TurmaForm()
    form.curso_id.choices = [(c.id, c.nome) for c in Curso.query.filter_by(status=1).order_by(Curso.nome).all()]
    
    if form.validate_on_submit():
        try:
            turma = Turma(
                nome=form.nome.data,
                curso_id=form.curso_id.data,
                local=form.local.data,
                periodo=form.periodo.data,
                ano=form.ano.data,
                semestre=form.semestre.data,
                status=form.status.data
            )
            db.session.add(turma)
            db.session.commit()
            flash('Turma cadastrada com sucesso!', 'success')
            return redirect(url_for('listar_turmas'))
        except Exception as e:
            db.session.rollback()
            flash(f'Erro ao cadastrar turma: {str(e)}', 'error')
    
    return render_template('turmas/form.html', form=form, titulo='Nova Turma')

@app.route('/turmas/<int:id>/editar', methods=['GET', 'POST'])
@login_required
def editar_turma(id):
    if session.get('user_tipo') not in ['admin', 'secretaria']:
        flash('Acesso negado!', 'error')
        return redirect(url_for('index'))
    
    turma = Turma.query.get_or_404(id)
    form = TurmaForm(obj=turma)
    form.curso_id.choices = [(c.id, c.nome) for c in Curso.query.filter_by(status=1).order_by(Curso.nome).all()]
    
    if form.validate_on_submit():
        try:
            turma.nome = form.nome.data
            turma.curso_id = form.curso_id.data
            turma.local = form.local.data
            turma.periodo = form.periodo.data
            turma.ano = form.ano.data
            turma.semestre = form.semestre.data
            turma.status = form.status.data
            
            db.session.commit()
            flash('Turma atualizada com sucesso!', 'success')
            return redirect(url_for('listar_turmas'))
        except Exception as e:
            db.session.rollback()
            flash(f'Erro ao atualizar turma: {str(e)}', 'error')
    
    return render_template('turmas/form.html', form=form, titulo='Editar Turma')

@app.route('/turmas/<int:id>/deletar', methods=['POST'])
@login_required
def deletar_turma(id):
    if session.get('user_tipo') not in ['admin', 'secretaria']:
        flash('Acesso negado!', 'error')
        return redirect(url_for('index'))
    
    turma = Turma.query.get_or_404(id)
    
    try:
        # Verificar se há alunos associados à turma antes de deletar
        if turma.alunos:
            flash('Não é possível excluir a turma pois há alunos vinculados a ela!', 'error')
            return redirect(url_for('listar_turmas'))
        
        db.session.delete(turma)
        db.session.commit()
        flash('Turma excluída com sucesso!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Erro ao excluir turma: {str(e)}', 'error')
    
    return redirect(url_for('listar_turmas'))

# Rotas para Notas (protegidas)
@app.route('/notas')
@login_required
def listar_notas():
    user_tipo = session.get('user_tipo')
    
    if user_tipo == 'aluno':
        aluno_id = session.get('user_id')
        # Organizar notas por disciplina
        notas = Nota.query.filter_by(aluno_id=aluno_id).order_by(Nota.disciplina_id, Nota.data).all()
        
        notas_por_disciplina = {}
        for nota in notas:
            if nota.disciplina not in notas_por_disciplina:
                notas_por_disciplina[nota.disciplina] = []
            notas_por_disciplina[nota.disciplina].append(nota)
        
        # Calcular médias por disciplina
        medias = {}
        for disciplina, notas_disc in notas_por_disciplina.items():
            valores = [n.valor for n in notas_disc]
            medias[disciplina.id] = sum(valores) / len(valores) if valores else None
        
        return render_template('notas/listar.html', 
                             notas_por_disciplina=notas_por_disciplina,
                             medias=medias)
    
    elif user_tipo == 'professor':
        professor_id = session.get('user_id')
        disciplinas_ids = [d.id for d in Disciplina.query.filter_by(professor_id=professor_id).all()]
        notas = Nota.query.filter(Nota.disciplina_id.in_(disciplinas_ids)).all()
        return render_template('notas/professor_listar.html', notas=notas)
    
    else:
        notas = Nota.query.all()
        return render_template('notas/admin_listar.html', notas=notas)

@app.route('/notas/nova', methods=['GET', 'POST'])
@login_required
def nova_nota():
    if session.get('user_tipo') == 'aluno':
        flash('Acesso negado!', 'error')
        return redirect(url_for('index'))
    
    form = NotaForm()
    
    # Filtrar opções baseado no tipo de usuário
    if session.get('user_tipo') == 'professor':
        professor_id = session.get('user_id')
        disciplinas = Disciplina.query.filter_by(professor_id=professor_id).all()
        form.disciplina_id.choices = [(d.id, d.nome) for d in disciplinas]
        
        # Alunos que têm notas nas disciplinas do professor
        alunos_ids = set()
        for disciplina in disciplinas:
            for nota in disciplina.notas:
                alunos_ids.add(nota.aluno_id)
        
        # Incluir todos os alunos para permitir novas notas
        alunos = Aluno.query.all()
        form.aluno_id.choices = [(a.id, a.nome) for a in alunos]
    else:
        form.aluno_id.choices = [(a.id, a.nome) for a in Aluno.query.all()]
        form.disciplina_id.choices = [(d.id, d.nome) for d in Disciplina.query.all()]
    
    if form.validate_on_submit():
        try:
            # Verificar se professor pode lançar nota nesta disciplina
            if session.get('user_tipo') == 'professor':
                disciplina = Disciplina.query.get(form.disciplina_id.data)
                if disciplina.professor_id != session.get('user_id'):
                    flash('Você só pode lançar notas em suas disciplinas!', 'error')
                    return render_template('notas/form.html', form=form, titulo='Nova Nota')
            
            nota = Nota(
                valor=form.valor.data,
                tipo=form.tipo.data,
                aluno_id=form.aluno_id.data,
                disciplina_id=form.disciplina_id.data
            )
            db.session.add(nota)
            db.session.commit()
            flash('Nota cadastrada com sucesso!', 'success')
            return redirect(url_for('listar_notas'))
        except Exception as e:
            db.session.rollback()
            flash(f'Erro ao cadastrar nota: {str(e)}', 'error')
    
    return render_template('notas/form.html', form=form, titulo='Nova Nota')

@app.route('/notas/<int:id>/editar', methods=['GET', 'POST'])
@login_required
def editar_nota(id):
    if session.get('user_tipo') == 'aluno':
        flash('Acesso negado!', 'error')
        return redirect(url_for('index'))
    
    nota = Nota.query.get_or_404(id)
    
    # Verificar se professor pode editar esta nota
    if session.get('user_tipo') == 'professor':
        if nota.disciplina.professor_id != session.get('user_id'):
            flash('Você só pode editar notas de suas disciplinas!', 'error')
            return redirect(url_for('listar_notas'))
    
    form = NotaForm(obj=nota)
    form.aluno_id.choices = [(a.id, a.nome) for a in Aluno.query.all()]
    form.disciplina_id.choices = [(d.id, d.nome) for d in Disciplina.query.all()]
    
    if form.validate_on_submit():
        try:
            nota.valor = form.valor.data
            nota.tipo = form.tipo.data
            nota.aluno_id = form.aluno_id.data
            nota.disciplina_id = form.disciplina_id.data
            db.session.commit()
            flash('Nota atualizada com sucesso!', 'success')
            return redirect(url_for('listar_notas'))
        except Exception as e:
            db.session.rollback()
            flash(f'Erro ao atualizar nota: {str(e)}', 'error')
    
    return render_template('notas/form.html', form=form, titulo='Editar Nota')

@app.route('/notas/<int:id>/deletar', methods=['POST'])
@login_required
def deletar_nota(id):
    if session.get('user_tipo') == 'aluno':
        flash('Acesso negado!', 'error')
        return redirect(url_for('index'))
    
    nota = Nota.query.get_or_404(id)
    
    # Verificar se professor pode deletar esta nota
    if session.get('user_tipo') == 'professor':
        if nota.disciplina.professor_id != session.get('user_id'):
            flash('Você só pode excluir notas de suas disciplinas!', 'error')
            return redirect(url_for('listar_notas'))
    
    try:
        db.session.delete(nota)
        db.session.commit()
        flash('Nota excluída com sucesso!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Erro ao excluir nota: {str(e)}', 'error')
    
    return redirect(url_for('listar_notas'))

@app.route('/minhas-aulas')
@login_required
def minhas_aulas():
    # Garante que apenas alunos acessem esta página
    if session.get('user_tipo') != 'aluno':
        flash('Acesso negado!', 'error')
        return redirect(url_for('index'))

    aluno_id = session.get('user_id')
    aluno = Aluno.query.get_or_404(aluno_id)

    # 1. Encontrar as disciplinas do aluno (baseado nas notas, como no dashboard)
    disciplinas_ids = {nota.disciplina_id for nota in aluno.notas}
    
    # 2. Buscar todas as aulas registradas para essas disciplinas
    aulas = Aula.query.filter(Aula.disciplina_id.in_(disciplinas_ids))\
                      .order_by(Aula.disciplina_id, Aula.data.desc())\
                      .all()
                      
    # 3. Agrupar as aulas por disciplina para facilitar a exibição no template
    aulas_por_disciplina = {}
    for aula in aulas:
        # Se a disciplina ainda não está no dicionário, adiciona
        if aula.disciplina not in aulas_por_disciplina:
            aulas_por_disciplina[aula.disciplina] = []
        # Adiciona a aula à lista da sua respectiva disciplina
        aulas_por_disciplina[aula.disciplina].append(aula)

    return render_template('aulas/aluno_listar.html', 
                         aulas_por_disciplina=aulas_por_disciplina,
                         total_aulas=len(aulas))

# Listar aulas registradas pelo professor
@app.route('/aulas')
@login_required
def listar_aulas():
    if session.get('user_tipo') != 'professor':
        flash('Acesso negado!', 'error')
        return redirect(url_for('index'))

    professor_id = session.get('user_id')
    aulas = Aula.query.filter_by(professor_id=professor_id).order_by(Aula.data.desc()).all()
    
    # Stats para os cards
    total_aulas = len(aulas)
    disciplinas_com_aulas = len(set(a.disciplina_id for a in aulas))
    
    return render_template('aulas/listar.html', 
                         aulas=aulas,
                         total_aulas=total_aulas,
                         disciplinas_com_aulas=disciplinas_com_aulas)

# Registrar uma nova aula
@app.route('/aulas/registrar', methods=['GET', 'POST'])
@login_required
def registrar_aula():
    if session.get('user_tipo') != 'professor':
        flash('Acesso negado!', 'error')
        return redirect(url_for('index'))

    form = AulaForm()
    professor_id = session.get('user_id')
    # Popula o dropdown apenas com as disciplinas do professor logado
    form.disciplina_id.choices = [(d.id, d.nome) for d in Disciplina.query.filter_by(professor_id=professor_id).all()]

    if form.validate_on_submit():
        try:
            nova_aula = Aula(
                data=form.data.data,
                hora_inicio=form.hora_inicio.data,
                hora_fim=form.hora_fim.data,
                conteudo=form.conteudo.data,
                observacoes=form.observacoes.data,
                disciplina_id=form.disciplina_id.data,
                professor_id=professor_id
            )
            db.session.add(nova_aula)
            db.session.commit()
            flash('Aula registrada com sucesso!', 'success')
            return redirect(url_for('listar_aulas'))
        except Exception as e:
            db.session.rollback()
            flash(f'Erro ao registrar aula: {str(e)}', 'error')
    
    return render_template('aulas/form.html', form=form, titulo='Registrar Nova Aula')

# Editar uma aula registrada
@app.route('/aulas/<int:id>/editar', methods=['GET', 'POST'])
@login_required
def editar_aula(id):
    aula = Aula.query.get_or_404(id)
    # Garante que o professor só pode editar sua própria aula
    if session.get('user_tipo') != 'professor' or aula.professor_id != session.get('user_id'):
        flash('Acesso negado!', 'error')
        return redirect(url_for('listar_aulas'))

    form = AulaForm(obj=aula)
    form.disciplina_id.choices = [(d.id, d.nome) for d in Disciplina.query.filter_by(professor_id=session.get('user_id')).all()]

    if form.validate_on_submit():
        try:
            aula.data = form.data.data
            aula.hora_inicio = form.hora_inicio.data
            aula.hora_fim = form.hora_fim.data
            aula.conteudo = form.conteudo.data
            aula.observacoes = form.observacoes.data
            aula.disciplina_id = form.disciplina_id.data
            db.session.commit()
            flash('Registro de aula atualizado com sucesso!', 'success')
            return redirect(url_for('listar_aulas'))
        except Exception as e:
            db.session.rollback()
            flash(f'Erro ao atualizar registro: {str(e)}', 'error')

    return render_template('aulas/form.html', form=form, titulo='Editar Registro de Aula')

# Deletar uma aula registrada
@app.route('/aulas/<int:id>/deletar', methods=['POST'])
@login_required
def deletar_aula(id):
    aula = Aula.query.get_or_404(id)
    if session.get('user_tipo') != 'professor' or aula.professor_id != session.get('user_id'):
        flash('Acesso negado!', 'error')
        return redirect(url_for('listar_aulas'))
    
    try:
        db.session.delete(aula)
        db.session.commit()
        flash('Registro de aula excluído com sucesso!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Erro ao excluir registro: {str(e)}', 'error')
        
    return redirect(url_for('listar_aulas'))

@app.route('/aulas/carregar-datas/<int:disciplina_id>')
@login_required
def carregar_datas_aula(disciplina_id):
    # Garante que é um professor
    if session.get('user_tipo') != 'professor':
        return jsonify({'error': 'Acesso negado'}), 403

    professor_id = session.get('user_id')
    
    # Busca todas as aulas daquela disciplina para o professor logado
    aulas = Aula.query.filter_by(
        disciplina_id=disciplina_id, 
        professor_id=professor_id
    ).order_by(Aula.data.desc()).all()
    
    # Cria uma lista de dicionários para o JSON, evitando datas duplicadas
    datas_unicas = sorted(list(set(a.data for a in aulas)), reverse=True)
    datas_json = [{'value': data.strftime('%Y-%m-%d'), 'text': data.strftime('%d/%m/%Y')} for data in datas_unicas]
    
    return jsonify(datas_json)

# Em app.py, adicione estas novas rotas

# Rota para renderizar a página do calendário do aluno
@app.route('/calendario/aluno')
@login_required
def calendario_aluno():
    if session.get('user_tipo') != 'aluno':
        flash('Acesso negado!', 'error')
        return redirect(url_for('index'))
    return render_template('calendario/aluno.html')

# API para fornecer os dados das aulas para o calendário
@app.route('/api/aulas/aluno')
@login_required
def api_aulas_aluno():
    if session.get('user_tipo') != 'aluno':
        return jsonify({'error': 'Acesso negado'}), 403

    aluno_id = session.get('user_id')
    aluno = Aluno.query.get_or_404(aluno_id)

    # Encontrar as disciplinas do aluno
    disciplinas_ids = {nota.disciplina_id for nota in aluno.notas}
    
    aulas = Aula.query.filter(Aula.disciplina_id.in_(disciplinas_ids)).all()
    
    eventos = []
    for aula in aulas:
        # ✨ COMBINA DATA E HORA ✨
        if aula.data and aula.hora_inicio and aula.hora_fim:
            start_datetime = datetime.combine(aula.data, aula.hora_inicio)
            end_datetime = datetime.combine(aula.data, aula.hora_fim)
            
            eventos.append({
                'title': aula.disciplina.nome,
                'start': start_datetime.isoformat(), # Envia data e hora
                'end': end_datetime.isoformat(),     # Envia data e hora
                # ... (resto das props) ...
                'extendedProps': {
                    'horario_str': f"{aula.hora_inicio.strftime('%H:%M')} - {aula.hora_fim.strftime('%H:%M')}",
                    'professor': aula.professor.nome,
                    'conteudo': aula.conteudo,
                    'observacoes': aula.observacoes
                }
            })
    return jsonify(eventos)

# Rota para renderizar a página do calendário do professor
@app.route('/calendario/professor')
@login_required
def calendario_professor():
    if session.get('user_tipo') != 'professor':
        flash('Acesso negado!', 'error')
        return redirect(url_for('index'))
    return render_template('calendario/professor.html')

# API para fornecer os dados das aulas do professor logado
@app.route('/api/aulas/professor')
@login_required
def api_aulas_professor():
    if session.get('user_tipo') != 'professor':
        return jsonify({'error': 'Acesso negado'}), 403

    professor_id = session.get('user_id')
    aulas = Aula.query.filter_by(professor_id=professor_id).all()
    
    eventos = []
    for aula in aulas:
        # ✨ COMBINA DATA E HORA ✨
        if aula.data and aula.hora_inicio and aula.hora_fim:
            start_datetime = datetime.combine(aula.data, aula.hora_inicio)
            end_datetime = datetime.combine(aula.data, aula.hora_fim)
            
            eventos.append({
                'title': aula.disciplina.nome,
                'start': start_datetime.isoformat(), # Envia data e hora
                'end': end_datetime.isoformat(),     # Envia data e hora
                # ... (resto das props) ...
                'extendedProps': {
                    'id': aula.id,
                    'horario_str': f"{aula.hora_inicio.strftime('%H:%M')} - {aula.hora_fim.strftime('%H:%M')}",
                    'turma': aula.disciplina.turma.nome if aula.disciplina.turma else 'Não definida',
                    'conteudo': aula.conteudo,
                    'observacoes': aula.observacoes
                }
            })
    return jsonify(eventos)

# Listar faltas (para professores)
@app.route('/faltas/professor', methods=['GET', 'POST'])
@login_required
def listar_faltas_professor():
    if session.get('user_tipo') != 'professor':
        flash('Acesso negado!', 'error')
        return redirect(url_for('index'))
    
    professor_id = session.get('user_id')
    
    # Obter disciplinas do professor
    disciplinas = Disciplina.query.filter_by(professor_id=professor_id).all()
    disciplinas_ids = [d.id for d in disciplinas]
    
    # Obter todas as faltas das disciplinas do professor
    faltas = Falta.query.filter(Falta.disciplina_id.in_(disciplinas_ids))\
                       .order_by(Falta.data.desc())\
                       .all()
    
    # Obter alunos matriculados nas disciplinas do professor
    alunos_por_disciplina = {}
    for disciplina in disciplinas:
        alunos_ids = {nota.aluno_id for nota in disciplina.notas}
        alunos = Aluno.query.filter(Aluno.id.in_(alunos_ids)).all()
        alunos_por_disciplina[disciplina.id] = alunos
    
    return render_template('faltas/professor_listar.html', 
                         faltas=faltas,
                         disciplinas=disciplinas,
                         alunos_por_disciplina=alunos_por_disciplina)

# Nova falta (para professores)
@app.route('/faltas/nova', methods=['GET', 'POST'])
@login_required
def nova_falta():
    if session.get('user_tipo') != 'professor':
        flash('Acesso negado!', 'error')
        return redirect(url_for('index'))
    
    form = FaltaForm()
    professor_id = session.get('user_id')
    
    # Popula o dropdown de disciplinas
    disciplinas_professor = Disciplina.query.filter_by(professor_id=professor_id).all()
    form.disciplina_id.choices = [(0, 'Selecione uma disciplina...')] + [(d.id, d.nome) for d in disciplinas_professor]
    
    # ✨ INÍCIO DA CORREÇÃO ✨
    # Se o formulário está sendo enviado (POST), precisamos popular as escolhas
    # dos campos dinâmicos ANTES da validação.
    if request.method == 'POST':
        disciplina_id_selecionada = request.form.get('disciplina_id', type=int)
        
        # Popula as datas de aula
        aulas = Aula.query.filter_by(disciplina_id=disciplina_id_selecionada, professor_id=professor_id).all()
        datas_unicas = sorted(list(set(a.data for a in aulas)), reverse=True)
        form.data_aula.choices = [(data.strftime('%Y-%m-%d'), data.strftime('%d/%m/%Y')) for data in datas_unicas]

        # Popula os alunos da turma
        disciplina = Disciplina.query.get(disciplina_id_selecionada)
        if disciplina and disciplina.turma_id:
            alunos_turma = Aluno.query.filter_by(turma_id=disciplina.turma_id).order_by(Aluno.nome).all()
            form.aluno_id.choices = [(a.id, a.nome) for a in alunos_turma]
        else:
            form.aluno_id.choices = []
    # ✨ FIM DA CORREÇÃO ✨

    if form.validate_on_submit():
        try:
            data_selecionada = datetime.strptime(form.data_aula.data, '%Y-%m-%d').date()

            falta = Falta(
                data=data_selecionada,
                motivo=form.motivo.data,
                aluno_id=form.aluno_id.data,
                disciplina_id=form.disciplina_id.data
            )
            db.session.add(falta)
            db.session.commit()
            flash('Falta registrada com sucesso!', 'success')
            return redirect(url_for('listar_faltas_professor'))
        except Exception as e:
            db.session.rollback()
            flash(f'Erro ao registrar falta: {str(e)}', 'error')
    
    return render_template('faltas/professor_form.html', 
                         form=form, 
                         titulo='Registrar Falta')

# Rota AJAX para carregar alunos da turma da disciplina das faltas
@app.route('/faltas/carregar-alunos/<int:disciplina_id>')
@login_required
def carregar_alunos_falta(disciplina_id):
    if session.get('user_tipo') != 'professor':
        return jsonify({'error': 'Acesso negado'}), 403
    
    disciplina = Disciplina.query.get_or_404(disciplina_id)
    
    # Verificar se o professor tem acesso a esta disciplina
    if disciplina.professor_id != session.get('user_id'):
        return jsonify({'error': 'Acesso negado'}), 403
    
    # Carregar alunos da turma associada à disciplina
    alunos = Aluno.query.filter_by(turma_id=disciplina.turma_id).order_by(Aluno.nome).all()
    
    alunos_json = [{'id': a.id, 'nome': a.nome, 'ra': a.ra} for a in alunos]
    return jsonify(alunos_json)

# Rota AJAX para carregar alunos da turma da disciplina das notas
@app.route('/notas/carregar-alunos/<int:disciplina_id>')
@login_required
def carregar_alunos_nota(disciplina_id):
    if session.get('user_tipo') != 'professor':
        return jsonify({'error': 'Acesso negado'}), 403
    
    disciplina = Disciplina.query.get_or_404(disciplina_id)
    
    # Verificar se o professor tem acesso a esta disciplina
    if disciplina.professor_id != session.get('user_id'):
        return jsonify({'error': 'Acesso negado'}), 403
    
    # Carregar alunos da turma associada à disciplina
    alunos = Aluno.query.filter_by(turma_id=disciplina.turma_id).order_by(Aluno.nome).all()
    
    alunos_json = [{'id': a.id, 'nome': a.nome, 'ra': a.ra} for a in alunos]
    return jsonify(alunos_json)

# Visualizar faltas para alunos
@app.route('/faltas/aluno')
@login_required
def listar_faltas_aluno():
    if session.get('user_tipo') != 'aluno':
        flash('Acesso negado!', 'error')
        return redirect(url_for('index'))
    
    aluno_id = session.get('user_id')
    aluno = Aluno.query.get_or_404(aluno_id)
    
    # Busca as faltas do aluno, ordenadas pela data mais recente
    faltas = Falta.query.filter_by(aluno_id=aluno_id).order_by(Falta.data.desc()).all()
    
    # Pega os IDs das disciplinas onde o aluno tem nota (ou seja, está matriculado)
    disciplinas_ids = {n.disciplina_id for n in aluno.notas}
    # Conta o total de aulas que foram registradas para essas disciplinas
    total_aulas_registradas = Aula.query.filter(Aula.disciplina_id.in_(disciplinas_ids)).count() if disciplinas_ids else 0
    
    return render_template('faltas/aluno_listar.html', 
                         faltas=faltas,
                         total_aulas_registradas=total_aulas_registradas)

# Deletar falta para professores
@app.route('/faltas/<int:id>/deletar', methods=['POST'])
@login_required
def deletar_falta(id):
    falta = Falta.query.get_or_404(id)
    
    # Adicionar verificação de permissão (extra, mas recomendado)
    if session.get('user_tipo') == 'professor':
        disciplina = Disciplina.query.get(falta.disciplina_id)
        if disciplina.professor_id != session.get('user_id'):
            flash('Acesso negado: você não pode excluir faltas de outras disciplinas.', 'error')
            return redirect(url_for('listar_faltas_professor'))

    try:
        db.session.delete(falta)
        db.session.commit()
        flash('Falta excluída com sucesso!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Erro ao excluir falta: {str(e)}', 'error')
    
    return redirect(url_for('listar_faltas_professor'))

# API para relatórios (protegida)
@app.route('/api/relatorio-notas/<int:aluno_id>')
@login_required
def relatorio_notas_aluno(aluno_id):
    # Verificar permissões
    user_tipo = session.get('user_tipo')
    if user_tipo == 'aluno' and session.get('user_id') != aluno_id:
        return jsonify({'erro': 'Acesso negado'}), 403
    elif user_tipo == 'professor':
        # Professor só pode ver notas de suas disciplinas
        professor_id = session.get('user_id')
        disciplinas_professor = [d.id for d in Disciplina.query.filter_by(professor_id=professor_id).all()]
        notas = Nota.query.filter_by(aluno_id=aluno_id).filter(Nota.disciplina_id.in_(disciplinas_professor)).all()
    else:
        notas = Nota.query.filter_by(aluno_id=aluno_id).all()
    
    aluno = Aluno.query.get_or_404(aluno_id)
    
    relatorio = {
        'aluno': aluno.nome,
        'notas': []
    }
    
    for nota in notas:
        relatorio['notas'].append({
            'disciplina': nota.disciplina.nome,
            'tipo': nota.tipo,
            'valor': nota.valor,
            'data': nota.data.strftime('%d/%m/%Y')
        })
    
    return jsonify(relatorio)

# Rota para alterar senha
@app.route('/alterar-senha', methods=['GET', 'POST'])
@login_required
def alterar_senha():
    if request.method == 'POST':
        senha_atual = request.form.get('senha_atual')
        nova_senha = request.form.get('nova_senha')
        confirmar_senha = request.form.get('confirmar_senha')
        
        if nova_senha != confirmar_senha:
            flash('As senhas não coincidem!', 'error')
            return render_template('auth/alterar_senha.html')
        
        if len(nova_senha) < 6:
            flash('A nova senha deve ter pelo menos 6 caracteres!', 'error')
            return render_template('auth/alterar_senha.html')
        
        try:
            user_tipo = session.get('user_tipo')
            user_id = session.get('user_id')
            
            if user_tipo in ['admin', 'secretaria']:
                usuario = Usuario.query.get(user_id)
                if usuario and usuario.check_password(senha_atual):
                    usuario.set_password(nova_senha)
                    db.session.commit()
                    flash('Senha alterada com sucesso!', 'success')
                    return redirect(url_for('index'))
                else:
                    flash('Senha atual incorreta!', 'error')
            
            elif user_tipo == 'professor':
                professor = Professor.query.get(user_id)
                if professor and professor.check_password(senha_atual):
                    professor.set_password(nova_senha)
                    db.session.commit()
                    flash('Senha alterada com sucesso!', 'success')
                    return redirect(url_for('index'))
                else:
                    flash('Senha atual incorreta!', 'error')
            
            elif user_tipo == 'aluno':
                aluno = Aluno.query.get(user_id)
                if aluno and aluno.check_password(senha_atual):
                    aluno.set_password(nova_senha)
                    db.session.commit()
                    flash('Senha alterada com sucesso!', 'success')
                    return redirect(url_for('index'))
                else:
                    flash('Senha atual incorreta!', 'error')
                    
        except Exception as e:
            db.session.rollback()
            flash(f'Erro ao alterar senha: {str(e)}', 'error')
    
    return render_template('auth/alterar_senha.html')

# Rota para perfil do usuário
@app.route('/perfil')
@login_required
def perfil():
    user_tipo = session.get('user_tipo')
    user_id = session.get('user_id')
    
    if user_tipo in ['admin', 'secretaria']:
        usuario = Usuario.query.get(user_id)
        return render_template('perfil/usuario.html', usuario=usuario)
    elif user_tipo == 'professor':
        professor = Professor.query.get(user_id)
        disciplinas = Disciplina.query.filter_by(professor_id=user_id).all()
        return render_template('perfil/professor.html', professor=professor, disciplinas=disciplinas)
    elif user_tipo == 'aluno':
        aluno = Aluno.query.get(user_id)
        notas = Nota.query.filter_by(aluno_id=user_id).all()
        return render_template('perfil/aluno.html', aluno=aluno, notas=notas)

# Rota de debug - listar usuários (REMOVER EM PRODUÇÃO)
@app.route('/debug-usuarios')
def debug_usuarios():
    try:
        resultado = {
            'usuarios': [],
            'professores': [],
            'alunos': []
        }
        
        # Usuários admin/secretaria
        usuarios = Usuario.query.all()
        for u in usuarios:
            resultado['usuarios'].append({
                'id': u.id,
                'nome': u.nome,
                'email': u.email,
                'tipo': u.tipo,
                'ativo': u.ativo,
                'tem_senha': bool(u.senha_hash)
            })
        
        # Professores
        professores = Professor.query.all()
        for p in professores:
            resultado['professores'].append({
                'id': p.id,
                'nome': p.nome,
                'email': p.email,
                'ativo': p.ativo,
                'tem_senha': bool(p.senha_hash)
            })
        
        # Alunos
        alunos = Aluno.query.all()
        for a in alunos:
            resultado['alunos'].append({
                'id': a.id,
                'nome': a.nome,
                'email': a.email,
                'ativo': a.ativo,
                'tem_senha': bool(a.senha_hash)
            })
        
        return jsonify(resultado)
    except Exception as e:
        return jsonify({'erro': str(e)})

def criar_admin_padrao():
    with app.app_context():
        try:
            # Verificar se já existe um admin com este email
            admin_existente = Usuario.query.filter_by(email='admin@escola.com').first()
            
            if admin_existente:
                print("❌ Já existe um administrador com email 'admin@escola.com'")
                print(f"   Nome: {admin_existente.nome}")
                print(f"   Email: {admin_existente.email}")
                print(f"   Tipo: {admin_existente.tipo}")
                print(f"   Ativo: {'Sim' if admin_existente.ativo else 'Não'}")
                return False
            
            # Criar o administrador padrão
            admin = Usuario(
                nome='Administrador',
                email='admin@escola.com',
                tipo='admin',
                ativo=True
            )
            
            # Definir a senha padrão 'admin'
            admin.set_password('admin')
            
            # Adicionar ao banco de dados
            db.session.add(admin)
            db.session.commit()
            
            print("✅ Administrador padrão criado com sucesso!")
            print("   📧 Email: admin@escola.com")
            print("   🔑 Senha: admin")
            print("   👤 Nome: Administrador")
            print("   🛡️  Tipo: admin")
            print("\n⚠️  IMPORTANTE: Altere a senha após o primeiro login!")
            
            return True
            
        except Exception as e:
            db.session.rollback()
            print(f"❌ Erro ao criar administrador: {e}")
            return False
        
if __name__ == '__main__':
    with app.app_context():
        # Inicializar o banco de dados
        init_db()
        print("Aplicação iniciada!")
        
        criar_admin_padrao()
        criar_cursos_iniciais()

        # Verificar se existem usuários
        total_usuarios = Usuario.query.count()
        total_professores = Professor.query.count()
        total_alunos = Aluno.query.count()
        
        print(f"Total de usuários admin/secretaria: {total_usuarios}")
        print(f"Total de professores: {total_professores}")
        print(f"Total de alunos: {total_alunos}")
        
    app.run(debug=True)