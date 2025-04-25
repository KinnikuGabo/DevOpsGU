import mysql.connector
import time
import os
from dotenv import load_dotenv
from mysql.connector import Error
from typing import Optional

# Cargar variables de entorno
load_dotenv()

def get_db_connection(max_retries: int = 30, retry_delay: int = 5) -> mysql.connector.MySQLConnection:
    """
    Establece conexión con la base de datos MySQL con reintentos automáticos.
    
    Args:
        max_retries: Número máximo de intentos de conexión
        retry_delay: Segundos a esperar entre intentos
        
    Returns:
        Objeto de conexión MySQL
        
    Raises:
        Exception: Si no se puede establecer la conexión después de los reintentos
    """
    retries = 0
    last_error = None
    
    db_config = {
        'host': os.getenv("DB_HOST", "db"),
        'user': os.getenv("DB_USER", "smartuser"),
        'password': os.getenv("DB_PASSWORD", "smartpass"),
        'database': os.getenv("DB_NAME", "smartdocs"),
        'port': 3306,
        'auth_plugin': 'mysql_native_password'
    }
    
    print(f"🔧 Intentando conectar a MySQL en {db_config['host']}...")
    
    while retries < max_retries:
        try:
            connection = mysql.connector.connect(**db_config)
            print("✅ Conexión a MySQL establecida correctamente")
            return connection
        except Error as err:
            retries += 1
            last_error = err
            print(f"⚠️ Error de conexión (intento {retries}/{max_retries}): {err}")
            if retries < max_retries:
                time.sleep(retry_delay)
    
    error_msg = f"❌ No se pudo conectar a MySQL después de {max_retries} intentos. Último error: {last_error}"
    print(error_msg)
    raise Exception(error_msg)

def init_db() -> None:
    """
    Inicializa la base de datos y crea las tablas si no existen.
    """
    print("⌛ Iniciando inicialización de la base de datos...")
    connection = None
    cursor = None
    
    try:
        # Esperar para asegurar que MySQL esté listo
        time.sleep(15)
        
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        
        # Verificar si las tablas principales ya existen
        cursor.execute("""
            SELECT COUNT(*) as table_count
            FROM information_schema.tables
            WHERE table_schema = DATABASE()
            AND table_name IN ('users', 'files', 'shared_files')
        """)
        result = cursor.fetchone()
        table_count = result['table_count']
        
        if table_count < 3:
            print("🔨 Creando tablas necesarias...")
            
            # Tabla de usuarios
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    email VARCHAR(255) NOT NULL UNIQUE,
                    password_hash VARCHAR(255) NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """)
            
            # Tabla de archivos
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS files (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT NOT NULL,
                    filename VARCHAR(255) NOT NULL,
                    filepath VARCHAR(255) NOT NULL,
                    filesize INT NOT NULL,
                    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    processed BOOLEAN DEFAULT FALSE,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """)
            
            # Tabla de archivos compartidos
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS shared_files (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    file_id INT NOT NULL,
                    owner_id INT NOT NULL,
                    shared_with_id INT NOT NULL,
                    shared_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE,
                    FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE,
                    FOREIGN KEY (shared_with_id) REFERENCES users(id) ON DELETE CASCADE,
                    UNIQUE KEY unique_share (file_id, shared_with_id)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """)
            
            connection.commit()
            print("✅ Base de datos inicializada correctamente")
        else:
            print("ℹ️ Las tablas ya existen, omitiendo creación")
            
    except Error as e:
        print(f"❌ Error durante la inicialización de la base de datos: {e}")
        if connection and connection.is_connected():
            connection.rollback()
        raise
    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()

def test_db_connection() -> bool:
    """
    Prueba la conexión a la base de datos.
    
    Returns:
        bool: True si la conexión es exitosa, False si falla
    """
    try:
        conn = get_db_connection(max_retries=1, retry_delay=1)
        conn.close()
        return True
    except Exception:
        return False

if __name__ == "__main__":
    # Para pruebas directas
    print("Probando conexión a la base de datos...")
    if test_db_connection():
        print("✅ Prueba de conexión exitosa")
    else:
        print("❌ Prueba de conexión fallida")
