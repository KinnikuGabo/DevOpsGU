from app.llm_integration import DocumentQASystem
from app.pdf_processing import VectorDatabase
from datetime import timedelta
from fastapi import FastAPI, Depends, HTTPException, status, UploadFile, File, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from typing import Annotated, Optional
import mysql.connector
from mysql.connector import Error
from jose import JWTError, jwt
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from app.database import get_db_connection, init_db
from app.models import UserCreate, UserLogin, UserInDB, ShareFileRequest
from app.utils import (get_password_hash, verify_password, 
                      create_access_token, ACCESS_TOKEN_EXPIRE_MINUTES,
                      SECRET_KEY, ALGORITHM)
import os
import shutil
import uuid
import logging
from werkzeug.utils import secure_filename
from typing import Dict
from typing import Any, Dict, List, Optional  # si usas más tipos


# Configuración inicial
app = FastAPI()

# Configuración de logging
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

# Middleware para límite de tamaño de archivos
@app.middleware("http")
async def check_file_size(request: Request, call_next):
    content_length = int(request.headers.get('content-length', 0))
    if content_length > 50 * 1024 * 1024:  # 50MB
        logger.warning(f"Intento de subida de archivo demasiado grande: {content_length} bytes")
        return JSONResponse(
            status_code=413,
            content={"detail": "El archivo excede el límite de 50MB"}
        )
    return await call_next(request)

# Configuración CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Inicialización de la aplicación
@app.on_event("startup")
async def startup_event():
    logger.info("⏳ Iniciando aplicación...")
    try:
        init_db()
        logger.info("✅ Base de datos lista")
    except Exception as e:
        logger.error(f"❌ Error crítico al iniciar: {e}")
        raise

# Configuración para almacenamiento de archivos
UPLOAD_DIRECTORY = "uploads"
os.makedirs(UPLOAD_DIRECTORY, exist_ok=True)

# Tipos de archivos permitidos
ALLOWED_EXTENSIONS = {'pdf', 'txt', 'docx'}

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# ========== Funciones Auxiliares ==========
async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Credenciales inválidas"
            )
        
        connection = get_db_connection()
        if not connection:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Error de conexión a la base de datos"
            )
            
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT id, email FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Usuario no encontrado"
            )
            
        return UserInDB(**user)
            
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales inválidas"
        )
    finally:
        if 'connection' in locals() and connection.is_connected():
            cursor.close()
            connection.close()

def sanitize_filename(filename: str) -> str:
    """Sanitiza el nombre del archivo y verifica la extensión"""
    filename = secure_filename(filename)
    extension = filename.split('.')[-1].lower()
    if extension not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Tipo de archivo no permitido. Extensiones permitidas: {', '.join(ALLOWED_EXTENSIONS)}"
        )
    return filename

# ========== Endpoints de Autenticación ==========
@app.post("/register/")
async def register(user: UserCreate):
    connection = get_db_connection()
    if not connection:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error de conexión a la base de datos"
        )
    
    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE email = %s", (user.email,))
        if cursor.fetchone():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="El email ya está registrado"
            )
        
        password_hash = get_password_hash(user.password)
        cursor.execute(
            "INSERT INTO users (email, password_hash) VALUES (%s, %s)",
            (user.email, password_hash)
        )
        connection.commit()
        
        logger.info(f"Nuevo usuario registrado: {user.email}")
        return {"message": "Usuario registrado exitosamente"}
    
    except Error as e:
        connection.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error de base de datos: {e}"
        )
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

@app.post("/token")
async def login(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    connection = get_db_connection()
    if not connection:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error de conexión a la base de datos"
        )
    
    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute(
            "SELECT * FROM users WHERE email = %s", 
            (form_data.username,)
        )
        user = cursor.fetchone()
        
        if not user or not verify_password(form_data.password, user["password_hash"]):
            logger.warning(f"Intento de inicio de sesión fallido para: {form_data.username}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Email o contraseña incorrectos",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": user["email"]}, 
            expires_delta=access_token_expires
        )
        
        logger.info(f"Usuario autenticado: {user['email']}")
        return {"access_token": access_token, "token_type": "bearer"}
    
    except Error as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error de base de datos: {e}"
        )
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

@app.get("/users/me")
async def read_users_me(current_user: UserInDB = Depends(get_current_user)):
    return current_user

# ========== Endpoints de Gestión de Archivos ==========
@app.post("/files/upload/")
async def upload_file(
    file: UploadFile = File(...),
    current_user: UserInDB = Depends(get_current_user)
):
    try:
        # Validar y sanitizar nombre de archivo
        safe_filename = sanitize_filename(file.filename)
        file_extension = safe_filename.split('.')[-1]
        unique_filename = f"{uuid.uuid4()}.{file_extension}"
        file_path = os.path.join(UPLOAD_DIRECTORY, unique_filename)
        
        # Guardar el archivo temporalmente primero
        temp_path = f"{file_path}.temp"
        with open(temp_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        
        # Aquí podrías agregar verificación de virus/escaneo
        
        # Mover a ubicación final
        os.rename(temp_path, file_path)
        
        # Registrar en base de datos
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        cursor.execute(
            "INSERT INTO files (user_id, filename, filepath, filesize) VALUES (%s, %s, %s, %s)",
            (current_user.id, safe_filename, file_path, os.path.getsize(file_path))
        )
        file_id = cursor.lastrowid
        connection.commit()
        
        logger.info(f"Archivo subido por usuario {current_user.id}: {safe_filename} (ID: {file_id})")
        
        return {
            "message": "Archivo subido exitosamente",
            "file_id": file_id,
            "filename": safe_filename
        }
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error al subir archivo: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Error al subir archivo: {str(e)}"
        )
    finally:
        if 'connection' in locals() and connection.is_connected():
            cursor.close()
            connection.close()

@app.delete("/files/delete/{file_id}")
async def delete_file(
    file_id: int,
    current_user: UserInDB = Depends(get_current_user)
):
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    try:
        # Verificar permisos
        cursor.execute("""
            SELECT filepath FROM files 
            WHERE id = %s AND user_id = %s
        """, (file_id, current_user.id))
        
        file = cursor.fetchone()
        if not file:
            raise HTTPException(
                status_code=404,
                detail="Archivo no encontrado o sin permisos"
            )

        # Eliminar archivo físico
        try:
            if os.path.exists(file['filepath']):
                os.remove(file['filepath'])
                logger.info(f"Archivo físico eliminado: {file['filepath']}")
        except OSError as e:
            logger.error(f"Error al eliminar archivo físico: {e}")
            raise HTTPException(
                status_code=500,
                detail="Error al eliminar el archivo físico"
            )

        # Eliminar de la base vectorial
        if hasattr(vector_db, 'remove_document'):
            vector_db.remove_document(file_id, current_user.id)

        # Eliminar registros de la base de datos
        cursor.execute("DELETE FROM shared_files WHERE file_id = %s", (file_id,))
        cursor.execute("DELETE FROM files WHERE id = %s", (file_id,))
        connection.commit()
        
        logger.info(f"Usuario {current_user.id} eliminó archivo ID {file_id}")

        return {"message": "Archivo eliminado exitosamente"}
    
    except Error as e:
        connection.rollback()
        logger.error(f"Error de base de datos al eliminar archivo: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Error de base de datos: {e}"
        )
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

@app.post("/files/share/")
async def share_file(
    share_request: ShareFileRequest,
    current_user: UserInDB = Depends(get_current_user)
):
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)
    
    try:
        # Verificar que el archivo existe y pertenece al usuario
        cursor.execute(
            "SELECT * FROM files WHERE id = %s AND user_id = %s",
            (share_request.file_id, current_user.id)
        )
        if not cursor.fetchone():
            raise HTTPException(
                status_code=404,
                detail="Archivo no encontrado o no pertenece al usuario"
            )
        
        # Verificar usuario destino
        cursor.execute(
            "SELECT id FROM users WHERE email = %s",
            (share_request.shared_with_email,)
        )
        shared_with_user = cursor.fetchone()
        if not shared_with_user:
            raise HTTPException(
                status_code=404,
                detail="Usuario destino no encontrado"
            )
        
        # Evitar compartir consigo mismo
        if shared_with_user["id"] == current_user.id:
            raise HTTPException(
                status_code=400,
                detail="No puedes compartir un archivo contigo mismo"
            )
        
        # Verificar si ya está compartido
        cursor.execute(
            "SELECT * FROM shared_files WHERE file_id = %s AND shared_with_id = %s",
            (share_request.file_id, shared_with_user["id"])
        )
        if cursor.fetchone():
            raise HTTPException(
                status_code=400,
                detail="El archivo ya está compartido con este usuario"
            )
        
        # Registrar el compartimiento
        cursor.execute(
            "INSERT INTO shared_files (file_id, owner_id, shared_with_id) VALUES (%s, %s, %s)",
            (share_request.file_id, current_user.id, shared_with_user["id"])
        )
        connection.commit()
        
        logger.info(f"Archivo {share_request.file_id} compartido por {current_user.id} con {shared_with_user['id']}")
        
        return {"message": "Archivo compartido exitosamente"}
    
    except Error as e:
        connection.rollback()
        logger.error(f"Error al compartir archivo: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Error de base de datos: {e}"
        )
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

@app.get("/files/my-files/")
async def get_my_files(
    current_user: UserInDB = Depends(get_current_user)
):
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)
    
    try:
        cursor.execute(
            "SELECT id, filename, filesize, uploaded_at FROM files WHERE user_id = %s",
            (current_user.id,)
        )
        return {"files": cursor.fetchall()}
    
    except Error as e:
        logger.error(f"Error al obtener archivos: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Error de base de datos: {e}"
        )
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

@app.get("/files/shared-with-me/")
async def get_shared_files(
    current_user: UserInDB = Depends(get_current_user)
):
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)
    
    try:
        cursor.execute("""
            SELECT f.id, f.filename, f.filesize, f.uploaded_at, u.email as owner_email 
            FROM files f
            JOIN shared_files sf ON f.id = sf.file_id
            JOIN users u ON sf.owner_id = u.id
            WHERE sf.shared_with_id = %s
        """, (current_user.id,))
        
        return {"files": cursor.fetchall()}
    
    except Error as e:
        logger.error(f"Error al obtener archivos compartidos: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Error de base de datos: {e}"
        )
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

@app.get("/files/download/{file_id}")
async def download_file(
    file_id: int,
    current_user: UserInDB = Depends(get_current_user)
):
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)
    
    try:
        cursor.execute("""
            SELECT f.* FROM files f
            WHERE f.id = %s AND (f.user_id = %s OR 
                  EXISTS (SELECT 1 FROM shared_files sf WHERE sf.file_id = f.id AND sf.shared_with_id = %s))
        """, (file_id, current_user.id, current_user.id))
        
        file = cursor.fetchone()
        if not file:
            raise HTTPException(
                status_code=404,
                detail="Archivo no encontrado o sin permisos"
            )
        
        if not os.path.exists(file["filepath"]):
            logger.error(f"Archivo no encontrado en ruta: {file['filepath']}")
            raise HTTPException(
                status_code=404,
                detail="Archivo no encontrado en el servidor"
            )
        
        logger.info(f"Descarga de archivo {file_id} por usuario {current_user.id}")
        
        return FileResponse(
            file["filepath"],
            filename=file["filename"],
            media_type='application/octet-stream'
        )
    
    except Error as e:
        logger.error(f"Error al descargar archivo: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Error de base de datos: {e}"
        )
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

# ========== Procesamiento de PDFs y Búsqueda ==========
vector_db = VectorDatabase()

@app.post("/files/process-pdf/{file_id}")
async def process_pdf(
    file_id: int,
    current_user: UserInDB = Depends(get_current_user)
):
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)
    
    try:
        cursor.execute(
            "SELECT * FROM files WHERE id = %s AND user_id = %s",
            (file_id, current_user.id)
        )
        file = cursor.fetchone()
        
        if not file:
            raise HTTPException(
                status_code=404,
                detail="Archivo no encontrado o sin permisos"
            )
        
        if not file['filepath'].endswith('.pdf'):
            raise HTTPException(
                status_code=400,
                detail="El archivo no es un PDF"
            )
        
        try:
            vector_db.add_document(file['filepath'], file_id, current_user.id)
            
            # Marcar como procesado en la base de datos
            cursor.execute(
                "UPDATE files SET processed = TRUE WHERE id = %s",
                (file_id,)
            )
            connection.commit()
            
            logger.info(f"PDF procesado exitosamente: {file_id}")
            
            return {
                "message": "PDF procesado exitosamente", 
                "file_id": file_id
            }
        except Exception as e:
            logger.error(f"Error al procesar PDF: {str(e)}")
            raise HTTPException(
                status_code=500,
                detail=str(e)
            )
            
    except Error as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error de base de datos: {e}"
        )
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

@app.get("/files/search")
async def search_files(
    query: str,
    current_user: UserInDB = Depends(get_current_user)
):
    try:
        results = vector_db.search(query, current_user.id)
        logger.info(f"Búsqueda realizada por {current_user.id}: '{query}'")
        return {"results": results}
    except Exception as e:
        logger.error(f"Error en búsqueda: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=str(e)
        )

# ========== Sistema de Preguntas y Respuestas ==========
qa_system = DocumentQASystem(model_name="llama3")

@app.get("/ask")
async def ask_question(
    question: str,
    file_id: int,
    current_user: UserInDB = Depends(get_current_user)
):
    try:
        # Verificar acceso al documento
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        cursor.execute("""
            SELECT f.filepath FROM files f
            WHERE f.id = %s AND (f.user_id = %s OR 
                EXISTS (SELECT 1 FROM shared_files sf WHERE sf.file_id = f.id AND sf.shared_with_id = %s))
        """, (file_id, current_user.id, current_user.id))
        
        file = cursor.fetchone()
        if not file:
            raise HTTPException(
                status_code=404,
                detail="Documento no encontrado o sin permisos"
            )

        # Verificar existencia física del archivo
        if not os.path.exists(file["filepath"]):
            raise HTTPException(
                status_code=404,
                detail="El archivo PDF no existe en el servidor"
            )

        # Buscar en el documento específico
        search_results = vector_db.search_in_document(question, current_user.id, file_id)
        
        if not search_results:
            return {
                "answer": f"No encontré información relevante en el documento {file_id}",
                "details": "El documento puede no haber sido procesado correctamente"
            }
        
        # Generar respuesta
        answer = qa_system.generate_response(search_results, question, file_id)
        
        logger.info(f"Pregunta respondida para usuario {current_user.id} en documento {file_id}")
        
        return {
            "answer": answer,
            "sources": [{
                "file_id": file_id,
                "excerpt": res["text"][:200] + "...",
                "score": res["score"]
            } for res in search_results]
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error al procesar pregunta: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Error al procesar la pregunta: {str(e)}"
        )
    finally:
        if 'connection' in locals() and connection.is_connected():
            cursor.close()
            connection.close()

# ========== Endpoints de Estado de Procesamiento ==========
@app.get("/files/processing-status/{file_id}")
async def get_processing_status(
    file_id: int,
    current_user: UserInDB = Depends(get_current_user)
):
    try:
        # Verificar acceso al archivo primero
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        cursor.execute("""
            SELECT processed FROM files 
            WHERE id = %s AND (user_id = %s OR 
                EXISTS (SELECT 1 FROM shared_files WHERE file_id = %s AND shared_with_id = %s))
        """, (file_id, current_user.id, file_id, current_user.id))
        
        file = cursor.fetchone()
        if not file:
            raise HTTPException(
                status_code=404,
                detail="Archivo no encontrado o sin permisos"
            )
        
        # Verificar en la base vectorial
        processed_in_vector = any(
            meta["file_id"] == file_id and meta["user_id"] == current_user.id
            for meta in vector_db.metadata
        )
        
        return {
            "processed": file["processed"] or processed_in_vector,
            "file_id": file_id
        }
        
    except Error as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error de base de datos: {e}"
        )
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

@app.post("/files/processing-status")
async def post_processing_status(
    request_data: Dict[str, int],
    current_user: UserInDB = Depends(get_current_user)
):
    if "file_id" not in request_data:
        raise HTTPException(
            status_code=400,
            detail="Se requiere file_id en el cuerpo de la solicitud"
        )
    
    file_id = request_data["file_id"]
    
    # Reutilizamos la lógica del endpoint GET
    response = await get_processing_status(file_id, current_user)
    return response