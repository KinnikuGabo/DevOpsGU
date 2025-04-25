from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory
import requests
import os
from dotenv import load_dotenv
from werkzeug.utils import secure_filename
import uuid
import redis
from datetime import timedelta
import json
import hashlib

# Cargar variables de entorno
load_dotenv()

# Configuración de Redis
REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
REDIS_DB = int(os.getenv("REDIS_DB", 0))
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", "")

# Cliente Redis
redis_client = redis.Redis(
    host=REDIS_HOST,
    port=REDIS_PORT,
    db=REDIS_DB,
    password=REDIS_PASSWORD,
    decode_responses=True
)

# Tiempo de expiración del cache (1 hora)
CACHE_EXPIRATION = int(timedelta(hours=1).total_seconds())

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "una-clave-secreta-muy-segura")

# Configuración de la API
API_BASE_URL = os.getenv("API_BASE_URL", "http://backend:8000")
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Cliente para la API con cache
class APIClient:
    def __init__(self, base_url):
        self.base_url = base_url
    
    def _get_headers(self):
        """Obtiene los headers de autenticación"""
        headers = {}
        if 'access_token' in session:
            headers['Authorization'] = f"Bearer {session['access_token']}"
        return headers
    
    def _generate_cache_key(self, endpoint: str, params: dict) -> str:
        """Genera una clave única para el cache basada en el endpoint y parámetros"""
        user_id = self.get_current_user().get('id', '') if self.get_current_user() else 'anonymous'
        sorted_params = sorted(params.items())
        param_str = "&".join(f"{k}={v}" for k, v in sorted_params)
        param_hash = hashlib.md5(param_str.encode()).hexdigest()
        return f"cache:{user_id}:{endpoint}:{param_hash}"
    
    def _get_cached_response(self, cache_key: str):
        """Obtiene respuesta del cache si existe"""
        try:
            cached_data = redis_client.get(cache_key)
            return json.loads(cached_data) if cached_data else None
        except (redis.RedisError, json.JSONDecodeError) as e:
            print(f"Error al acceder a Redis: {e}")
            return None
    
    def _set_cached_response(self, cache_key: str, data: dict):
        """Almacena respuesta en cache"""
        try:
            redis_client.setex(cache_key, CACHE_EXPIRATION, json.dumps(data))
        except redis.RedisError as e:
            print(f"Error al guardar en Redis: {e}")
    
    def invalidate_cache_for_file(self, file_id: int):
        """Invalida todas las entradas de cache relacionadas con un archivo"""
        try:
            user_id = self.get_current_user().get('id', '') if self.get_current_user() else '*'
            pattern = f"cache:{user_id}:*:file_id={file_id}*"
            keys = redis_client.keys(pattern)
            if keys:
                redis_client.delete(*keys)
                print(f"Invalidadas {len(keys)} entradas de cache para el archivo {file_id}")
        except redis.RedisError as e:
            print(f"Error al invalidar cache: {e}")

    # Métodos de autenticación
    def login(self, email, password):
        url = f"{self.base_url}/token"
        data = {
            "username": email,
            "password": password,
            "grant_type": "password"
        }
        response = requests.post(url, data=data)
        if response.status_code == 200:
            return response.json()
        return None
    
    def register(self, email, password):
        url = f"{self.base_url}/register/"
        data = {
            "email": email,
            "password": password
        }
        response = requests.post(url, json=data)
        return response.status_code == 200
    
    def get_current_user(self):
        url = f"{self.base_url}/users/me"
        response = requests.get(url, headers=self._get_headers())
        if response.status_code == 200:
            return response.json()
        return None
    
    # Métodos de gestión de archivos con cache
    def upload_file(self, file):
        url = f"{self.base_url}/files/upload/"
        files = {'file': (file.filename, file.stream, file.content_type)}
        response = requests.post(url, files=files, headers=self._get_headers())
        if response.status_code == 200:
            self.invalidate_cache_for_file(response.json().get('file_id'))
            return response.json()
        return None
    
    def get_my_files(self):
        url = f"{self.base_url}/files/my-files/"
        response = requests.get(url, headers=self._get_headers())
        return response.json().get('files', []) if response.status_code == 200 else []
    
    def get_shared_files(self):
        url = f"{self.base_url}/files/shared-with-me/"
        response = requests.get(url, headers=self._get_headers())
        return response.json().get('files', []) if response.status_code == 200 else []
    
    def delete_file(self, file_id):
        url = f"{self.base_url}/files/delete/{file_id}"
        response = requests.delete(url, headers=self._get_headers())
        if response.status_code == 200:
            self.invalidate_cache_for_file(file_id)
            return True
        return False
    
    def share_file(self, file_id, email):
        url = f"{self.base_url}/files/share/"
        data = {
            "file_id": file_id,
            "shared_with_email": email
        }
        response = requests.post(url, json=data, headers=self._get_headers())
        if response.status_code == 200:
            self.invalidate_cache_for_file(file_id)
            return True
        return False
    
    def process_pdf(self, file_id):
        url = f"{self.base_url}/files/process-pdf/{file_id}"
        response = requests.post(url, headers=self._get_headers())
        if response.status_code == 200:
            self.invalidate_cache_for_file(file_id)
            return True
        return False
    
    # Métodos con cache implementado
    def search_files(self, query):
        cache_key = self._generate_cache_key("search", {"query": query})
        cached = self._get_cached_response(cache_key)
        if cached is not None:
            print("Respuesta obtenida del cache")
            return cached
            
        url = f"{self.base_url}/files/search"
        params = {'query': query}
        response = requests.get(url, params=params, headers=self._get_headers())
        
        if response.status_code == 200:
            data = response.json().get('results', [])
            self._set_cached_response(cache_key, data)
            return data
        return []
    
    def ask_question(self, question, file_id):
        cache_key = self._generate_cache_key("ask", {"question": question, "file_id": file_id})
        cached = self._get_cached_response(cache_key)
        if cached is not None:
            print("Respuesta obtenida del cache")
            return cached
            
        url = f"{self.base_url}/ask"
        params = {
            'question': question,
            'file_id': file_id
        }
        response = requests.get(url, params=params, headers=self._get_headers())
        
        if response.status_code == 200:
            data = response.json()
            self._set_cached_response(cache_key, data)
            return data
        return None
    
    def download_file(self, file_id):
        url = f"{self.base_url}/files/download/{file_id}"
        response = requests.get(url, headers=self._get_headers(), stream=True)
        if response.status_code == 200:
            filename = response.headers.get('content-disposition').split('filename=')[1].strip('"')
            temp_path = os.path.join(UPLOAD_FOLDER, str(uuid.uuid4()) + "_" + filename)
            with open(temp_path, 'wb') as f:
                for chunk in response.iter_content(1024):
                    f.write(chunk)
            return temp_path, filename
        return None, None

# Instancia del cliente API
api_client = APIClient(API_BASE_URL)

# Inyectar api_client en los templates
@app.context_processor
def inject_api_client():
    return dict(api_client=api_client)

# Middleware para verificar autenticación
@app.before_request
def before_request():
    if request.endpoint in ['login', 'register', 'static', 'health_check']:
        return
    
    if 'access_token' not in session:
        return redirect(url_for('login'))
    
    current_user = api_client.get_current_user()
    if not current_user:
        session.pop('access_token', None)
        flash('Sesión expirada, por favor inicia sesión nuevamente', 'warning')
        return redirect(url_for('login'))

# Endpoint de salud
@app.route('/health')
def health_check():
    try:
        redis_client.ping()
        return 'OK', 200
    except redis.RedisError:
        return 'Redis unavailable', 500

# Rutas de autenticación
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        response = api_client.login(email, password)
        if response:
            session['access_token'] = response['access_token']
            flash('Inicio de sesión exitoso', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Email o contraseña incorrectos', 'danger')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        if api_client.register(email, password):
            flash('Registro exitoso, por favor inicia sesión', 'success')
            return redirect(url_for('login'))
        else:
            flash('Error al registrar el usuario', 'danger')
    
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.pop('access_token', None)
    flash('Sesión cerrada correctamente', 'info')
    return redirect(url_for('login'))

# Rutas principales
@app.route('/')
def dashboard():
    current_user = api_client.get_current_user()
    if not current_user:
        return redirect(url_for('login'))
    
    my_files = api_client.get_my_files()
    shared_files = api_client.get_shared_files()
    
    return render_template('dashboard.html', 
                         my_files=my_files, 
                         shared_files=shared_files,
                         current_user=current_user)

@app.route('/files')
def files():
    my_files = api_client.get_my_files()
    return render_template('files.html', files=my_files)

@app.route('/shared')
def shared_files():
    shared_files = api_client.get_shared_files()
    return render_template('shared.html', files=shared_files)

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No se seleccionó ningún archivo', 'danger')
            return redirect(request.url)
        
        file = request.files['file']
        if file.filename == '':
            flash('No se seleccionó ningún archivo', 'danger')
            return redirect(request.url)
        
        response = api_client.upload_file(file)
        if response:
            flash('Archivo subido exitosamente', 'success')
            return redirect(url_for('files'))
        else:
            flash('Error al subir el archivo', 'danger')
    
    return render_template('upload.html')

@app.route('/delete/<int:file_id>')
def delete_file(file_id):
    if api_client.delete_file(file_id):
        flash('Archivo eliminado exitosamente', 'success')
    else:
        flash('Error al eliminar el archivo', 'danger')
    return redirect(url_for('files'))

@app.route('/share/<int:file_id>', methods=['POST'])
def share_file(file_id):
    email = request.form.get('email')
    if api_client.share_file(file_id, email):
        flash(f'Archivo compartido con {email}', 'success')
    else:
        flash(f'Error al compartir el archivo con {email}', 'danger')
    return redirect(url_for('files'))

@app.route('/process/<int:file_id>')
def process_file(file_id):
    if api_client.process_pdf(file_id):
        flash('Archivo enviado para procesamiento', 'success')
    else:
        flash('Error al procesar el archivo', 'danger')
    return redirect(url_for('files'))

@app.route('/search', methods=['GET', 'POST'])
def search():
    results = []
    if request.method == 'POST':
        query = request.form.get('query')
        results = api_client.search_files(query)
    return render_template('search.html', results=results)

@app.route('/ask', methods=['GET', 'POST'])
def ask():
    answer = None
    file_id = request.args.get('file_id', type=int)
    
    if request.method == 'POST':
        question = request.form.get('question')
        file_id = request.form.get('file_id', type=int)
        response = api_client.ask_question(question, file_id)
        if response:
            answer = response.get('answer', 'No se pudo obtener una respuesta')
    
    my_files = api_client.get_my_files()
    shared_files = api_client.get_shared_files()
    all_files = my_files + shared_files
    
    return render_template('ask.html', files=all_files, answer=answer, selected_file_id=file_id)

@app.route('/download/<int:file_id>')
def download_file(file_id):
    file_path, filename = api_client.download_file(file_id)
    if file_path and filename:
        try:
            return send_from_directory(
                directory=os.path.dirname(file_path),
                path=os.path.basename(file_path),
                as_attachment=True,
                download_name=filename
            )
        finally:
            try:
                os.remove(file_path)
            except:
                pass
    else:
        flash('Error al descargar el archivo', 'danger')
        return redirect(url_for('files'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)