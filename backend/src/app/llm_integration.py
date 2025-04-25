import requests
from typing import List, Dict
import json
import os

# Configuración de Ollama
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "ollama")
OLLAMA_URL = f"http://{OLLAMA_HOST}:11434/api/generate"

class DocumentQASystem:
    def __init__(self, model_name: str = "llama3"):
        self.model_name = model_name
    
    def generate_response(self, context: List[Dict], question: str, file_id: int) -> str:
        """
        Genera una respuesta basada en un único documento específico
        
        Args:
            context: Fragmentos relevantes del documento
            question: Pregunta del usuario
            file_id: ID del documento sobre el que se pregunta
        """
        # Formatear el contexto de manera más clara para un solo documento
        context_str = "\n---\n".join([
            f"Fragmento {i+1} (relevancia: {doc['score']:.2f}):\n{doc['text']}" 
            for i, doc in enumerate(context)
        ])
        
        prompt = f"""Instrucciones:
- Vas a responder una pregunta sobre un documento específico (ID: {file_id})
- Solo debes usar la información proporcionada en los fragmentos del documento
- Si la pregunta no puede responderse con este documento, di exactamente: 
  'No encontré información relevante en este documento'
- Usa citas textuales entre comillas cuando sea posible

Fragmentos del documento:
{context_str}

Pregunta: {question}

Respuesta:"""
        
        payload = {
            "model": self.model_name,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.2,  # Más bajo para mayor precisión
                "num_ctx": 4096,
                "num_predict": 350,  # Respuestas más concisas
                "repeat_penalty": 1.1  # Evitar repeticiones
            }
        }
        
        try:
            response = requests.post(
                OLLAMA_URL,
                json=payload,
                timeout=600  # 10 minutos deberían ser suficientes
            )
            
            if response.status_code != 200:
                error_msg = f"Error en Ollama (Código {response.status_code}): {response.text[:200]}..."
                return error_msg
                
            full_response = response.json()
            
            # Limpieza básica de la respuesta
            answer = full_response.get("response", "").strip()
            if not answer:
                return "El modelo no generó una respuesta válida"
                
            # Eliminar posibles repeticiones del prompt
            if "Fragmentos del documento:" in answer:
                answer = answer.split("Fragmentos del documento:")[0].strip()
                
            return answer
            
        except requests.exceptions.Timeout:
            return "Error: Tiempo de espera agotado. Por favor intenta con una pregunta más específica."
        except requests.exceptions.RequestException as e:
            return f"Error de conexión: {str(e)}"
        except Exception as e:
            return f"Error inesperado: {str(e)}"