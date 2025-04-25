import os
import numpy as np
import faiss
from PyPDF2 import PdfReader
from sentence_transformers import SentenceTransformer
from typing import List, Dict, Optional, Tuple
import logging
import re
import hashlib
import pickle
import base64
from pymongo import MongoClient
from pymongo.errors import PyMongoError
from pathlib import Path
from bson.binary import Binary
from datetime import datetime

# Configuración de logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

class VectorDatabase:
    def __init__(self, mongo_uri: str = "mongodb://root:example@mongodb:27017/"):
        """
        Inicializa la base de datos vectorial con conexión a MongoDB
        
        Args:
            mongo_uri: URI de conexión a MongoDB
        """
        self.model = self._initialize_model()
        self.index = None
        self.metadata = []
        self.client = MongoClient(mongo_uri)
        self.db = self.client.smartdocs
        self.vector_collection = self.db.vector_index
        self._load_index_from_mongo()

    def _initialize_model(self) -> SentenceTransformer:
        """Inicializa el modelo de embeddings con configuración robusta"""
        try:
            # Modelo más eficiente para producción
            model = SentenceTransformer('all-MiniLM-L6-v2', device='cpu')
            logger.info("Modelo de embeddings cargado exitosamente")
            return model
        except Exception as e:
            logger.error(f"Error al cargar el modelo: {e}")
            raise RuntimeError("No se pudo inicializar el modelo de embeddings")

    def _load_index_from_mongo(self) -> None:
        """Carga un índice existente desde MongoDB"""
        try:
            index_data = self.vector_collection.find_one({"type": "main_index"})
            
            if index_data:
                # Cargar índice FAISS
                self.index = pickle.loads(base64.b64decode(index_data["index"]))
                
                # Cargar metadatos
                self.metadata = index_data.get("metadata", [])
                
                logger.info(f"Índice vectorial cargado con {len(self.metadata)} documentos")
            else:
                logger.info("No se encontró índice existente, se creará uno nuevo")
                
        except Exception as e:
            logger.error(f"Error al cargar índice desde MongoDB: {e}")
            self.index = None
            self.metadata = []

    def _save_index_to_mongo(self) -> None:
        """Guarda el índice y metadatos en MongoDB"""
        try:
            if self.index is not None:
                # Serializar el índice FAISS
                index_bytes = base64.b64encode(pickle.dumps(self.index)).decode('utf-8')
                
                # Actualizar o insertar en MongoDB
                self.vector_collection.update_one(
                    {"type": "main_index"},
                    {"$set": {
                        "index": index_bytes,
                        "metadata": self.metadata,
                        "last_updated": datetime.utcnow()
                    }},
                    upsert=True
                )
                logger.info("Índice guardado exitosamente en MongoDB")
                
        except PyMongoError as e:
            logger.error(f"Error al guardar índice en MongoDB: {e}")
            raise RuntimeError(f"Error al guardar índice: {str(e)}")

    def extract_text_from_pdf(self, file_path: str) -> str:
        """
        Extrae texto de un PDF con manejo robusto de errores y mejoras de rendimiento
        
        Args:
            file_path: Ruta al archivo PDF
            
        Returns:
            Texto extraído del PDF
            
        Raises:
            ValueError: Si el PDF está vacío, corrupto o no se puede leer
        """
        try:
            file_path = Path(file_path)
            if not file_path.exists():
                raise ValueError(f"El archivo {file_path} no existe")

            text = []
            with file_path.open('rb') as f:
                reader = PdfReader(f)
                
                if len(reader.pages) == 0:
                    raise ValueError("PDF vacío o corrupto")
                
                for page in reader.pages:
                    try:
                        page_text = page.extract_text()
                        if page_text:
                            # Limpieza más eficiente del texto
                            cleaned_text = re.sub(r'\s+', ' ', page_text).strip()
                            text.append(cleaned_text)
                    except Exception as page_error:
                        logger.warning(f"Error al extraer texto de página: {page_error}")
                        continue

            full_text = '\n'.join(text)
            
            if not full_text.strip():
                raise ValueError("No se pudo extraer texto legible del PDF")

            logger.info(f"Texto extraído correctamente de {file_path} ({len(full_text)} caracteres)")
            return full_text

        except Exception as e:
            logger.error(f"Error al procesar PDF {file_path}: {e}")
            raise ValueError(f"Error procesando PDF: {str(e)}")

    def _split_text(self, text: str, chunk_size: int = 500, overlap: int = 50) -> List[str]:
        """
        Divide el texto en chunks con overlap para mantener contexto
        (Versión optimizada para mejor rendimiento)
        
        Args:
            text: Texto a dividir
            chunk_size: Tamaño máximo de cada chunk (en palabras)
            overlap: Palabras de solapamiento entre chunks
            
        Returns:
            Lista de chunks de texto
        """
        words = text.split()
        chunks = []
        start = 0
        total_words = len(words)
        
        while start < total_words:
            end = min(start + chunk_size, total_words)
            chunk = ' '.join(words[start:end])
            chunks.append(chunk)
            start = end - overlap if (end - overlap) > start else end
        
        return chunks

    def _generate_document_hash(self, file_path: str) -> str:
        """Genera un hash único para el documento usando SHA-256 (más seguro que MD5)"""
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
        return sha256.hexdigest()

    def add_document(self, file_path: str, file_id: int, user_id: int) -> None:
        """
        Procesa y añade un documento a la base de datos vectorial con optimizaciones
        
        Args:
            file_path: Ruta al archivo PDF
            file_id: ID del archivo en la base de datos
            user_id: ID del usuario propietario
            
        Raises:
            ValueError: Si hay problemas procesando el documento
        """
        try:
            logger.info(f"Iniciando procesamiento de documento {file_id} (Usuario: {user_id})")

            # Verificar existencia del archivo
            if not Path(file_path).exists():
                raise ValueError(f"El archivo {file_path} no existe")

            # Extraer texto
            text = self.extract_text_from_pdf(file_path)
            if not text:
                raise ValueError("No se pudo extraer texto del PDF")

            # Dividir en chunks optimizado
            chunks = self._split_text(text)
            if not chunks:
                raise ValueError("No se generaron chunks válidos del texto")

            logger.info(f"Documento dividido en {len(chunks)} chunks")

            # Generar embeddings por lotes para mejor rendimiento
            embeddings = self.model.encode(chunks, 
                                         batch_size=32,
                                         show_progress_bar=False,
                                         convert_to_numpy=True)
            logger.info(f"Embeddings generados: {embeddings.shape}")

            # Generar hash seguro del documento
            doc_hash = self._generate_document_hash(file_path)

            # Crear metadatos optimizados
            file_metadata = {
                "file_id": file_id,
                "user_id": user_id,
                "original_path": file_path,
                "document_hash": doc_hash,
                "chunk_count": len(chunks),
                "created_at": datetime.utcnow(),
                "chunks": chunks  # Guardamos los chunks para referencia
            }

            # Inicializar índice si no existe
            if self.index is None:
                self.index = faiss.IndexFlatIP(embeddings.shape[1])  # Uso Inner Product para similitud coseno
                self.metadata = []
                logger.info("Nuevo índice FAISS creado")

            # Añadir al índice
            self.index.add(embeddings)
            self.metadata.append(file_metadata)
            self._save_index_to_mongo()

            logger.info(f"Documento {file_id} añadido exitosamente al índice vectorial")

        except Exception as e:
            logger.error(f"Error al añadir documento {file_id}: {e}")
            raise ValueError(f"Error procesando documento: {str(e)}")

    def remove_document(self, file_id: int, user_id: int) -> bool:
        """
        Elimina un documento de la base de datos vectorial (versión optimizada)
        
        Args:
            file_id: ID del archivo a eliminar
            user_id: ID del usuario propietario
            
        Returns:
            True si se eliminó, False si no se encontró
            
        Raises:
            RuntimeError: Si ocurre un error durante la eliminación
        """
        try:
            if self.index is None or not self.metadata:
                return False

            # Encontrar documentos a eliminar
            docs_to_remove = [
                (i, meta) for i, meta in enumerate(self.metadata) 
                if meta["file_id"] == file_id and meta["user_id"] == user_id
            ]

            if not docs_to_remove:
                logger.info(f"Documento {file_id} no encontrado en el índice")
                return False

            # Reconstruir índice excluyendo los documentos eliminados
            remaining_metadata = [
                meta for meta in self.metadata 
                if not (meta["file_id"] == file_id and meta["user_id"] == user_id)
            ]

            if remaining_metadata:
                # Regenerar embeddings solo para los chunks restantes
                all_chunks = []
                for meta in remaining_metadata:
                    all_chunks.extend(meta["chunks"])

                embeddings = self.model.encode(all_chunks, show_progress_bar=False)
                
                # Crear nuevo índice
                new_index = faiss.IndexFlatIP(embeddings.shape[1])
                new_index.add(embeddings)
                
                self.index = new_index
                self.metadata = remaining_metadata
            else:
                self.index = None
                self.metadata = []

            self._save_index_to_mongo()
            logger.info(f"Documento {file_id} eliminado del índice vectorial")
            return True

        except Exception as e:
            logger.error(f"Error al eliminar documento {file_id}: {e}")
            raise RuntimeError(f"Error eliminando documento: {str(e)}")

    def search(self, query: str, user_id: int, k: int = 5) -> List[Dict]:
        """
        Busca en todos los documentos del usuario (versión optimizada)
        
        Args:
            query: Texto de búsqueda
            user_id: ID del usuario
            k: Número de resultados a devolver
            
        Returns:
            Lista de resultados relevantes con scores normalizados
        """
        if self.index is None or not self.metadata:
            return []

        try:
            # Generar embedding para la consulta
            query_embedding = self.model.encode([query], show_progress_bar=False)
            
            # Buscar en el índice (usando Inner Product)
            distances, indices = self.index.search(query_embedding, k)
            
            # Procesar resultados y normalizar scores
            results = []
            for idx, score in zip(indices[0], distances[0]):
                if 0 <= idx < len(self.metadata):
                    meta = self.metadata[idx]
                    if meta["user_id"] == user_id:
                        # Normalizar score a rango [0,1]
                        normalized_score = (score + 1) / 2  
                        results.append({
                            "file_id": meta["file_id"],
                            "text": meta["chunks"][idx % len(meta["chunks"])],
                            "score": float(normalized_score),
                            "original_path": meta["original_path"]
                        })
            
            logger.info(f"Búsqueda para usuario {user_id} devolvió {len(results)} resultados")
            return sorted(results, key=lambda x: x["score"], reverse=True)

        except Exception as e:
            logger.error(f"Error en búsqueda: {e}")
            raise RuntimeError(f"Error en búsqueda: {str(e)}")

    def search_in_document(self, query: str, user_id: int, file_id: int, k: int = 3) -> List[Dict]:
        """
        Busca solo dentro de un documento específico (versión optimizada)
        
        Args:
            query: Texto de búsqueda
            user_id: ID del usuario
            file_id: ID del documento específico
            k: Número de resultados a devolver
            
        Returns:
            Lista de resultados relevantes del documento especificado
        """
        if self.index is None:
            return []

        try:
            # Filtrar chunks del documento específico
            relevant_chunks = []
            chunk_indices = []
            
            for meta_idx, meta in enumerate(self.metadata):
                if meta["user_id"] == user_id and meta["file_id"] == file_id:
                    relevant_chunks.extend(meta["chunks"])
                    chunk_indices.extend([(meta_idx, i) for i in range(len(meta["chunks"]))])

            if not relevant_chunks:
                return []

            # Generar embeddings para los chunks relevantes (por lotes)
            chunk_embeddings = self.model.encode(relevant_chunks, show_progress_bar=False)
            
            # Generar embedding para la consulta
            query_embedding = self.model.encode([query], show_progress_bar=False)
            
            # Buscar usando FAISS con índice temporal
            temp_index = faiss.IndexFlatIP(chunk_embeddings.shape[1])
            temp_index.add(chunk_embeddings)
            scores, indices = temp_index.search(query_embedding, k)
            
            # Preparar resultados con scores normalizados
            results = []
            for idx, score in zip(indices[0], scores[0]):
                if 0 <= idx < len(relevant_chunks):
                    meta_idx, chunk_idx = chunk_indices[idx]
                    meta = self.metadata[meta_idx]
                    normalized_score = (score + 1) / 2  # Normalizar a [0,1]
                    results.append({
                        "file_id": file_id,
                        "text": relevant_chunks[idx],
                        "score": float(normalized_score),
                        "original_path": meta["original_path"]
                    })

            logger.info(f"Búsqueda en documento {file_id} devolvió {len(results)} resultados")
            return sorted(results, key=lambda x: x["score"], reverse=True)

        except Exception as e:
            logger.error(f"Error en búsqueda en documento {file_id}: {e}")
            raise RuntimeError(f"Error en búsqueda en documento: {str(e)}")

    def get_document_info(self, file_id: int, user_id: int) -> Optional[Dict]:
        """
        Obtiene metadatos de un documento específico (versión optimizada)
        
        Args:
            file_id: ID del documento
            user_id: ID del usuario propietario
            
        Returns:
            Metadatos del documento o None si no se encuentra
        """
        for meta in self.metadata:
            if meta["file_id"] == file_id and meta["user_id"] == user_id:
                return {
                    "file_id": meta["file_id"],
                    "user_id": meta["user_id"],
                    "chunk_count": meta["chunk_count"],
                    "document_hash": meta["document_hash"],
                    "original_path": meta["original_path"],
                    "created_at": meta.get("created_at")
                }
        return None

    def document_exists(self, file_id: int, user_id: int) -> bool:
        """Verifica si un documento existe en el índice (versión optimizada)"""
        return any(
            meta["file_id"] == file_id and meta["user_id"] == user_id
            for meta in self.metadata
        )

    def close(self):
        """Libera recursos y cierra conexiones"""
        if hasattr(self, 'client'):
            self.client.close()
            logger.info("Conexión a MongoDB cerrada")