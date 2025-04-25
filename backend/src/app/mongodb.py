from pymongo import MongoClient
from pymongo.errors import PyMongoError
from typing import Dict, List
import os

class MongoDB:
    def __init__(self):
        self.client = MongoClient(
            host="mongodb",
            username="root",
            password="example",
            authSource="admin"
        )
        self.db = self.client.smartdocs
        self.chat_history = self.db.chat_history
    
    def save_query(self, user_id: int, file_id: int, question: str, answer: str):
        try:
            self.chat_history.insert_one({
                "user_id": user_id,
                "file_id": file_id,
                "question": question,
                "answer": answer,
                "timestamp": datetime.utcnow()
            })
        except PyMongoError as e:
            logger.error(f"Error al guardar historial: {e}")

    def get_history(self, user_id: int, file_id: int, limit: int = 10) -> List[Dict]:
        try:
            return list(self.chat_history.find(
                {"user_id": user_id, "file_id": file_id},
                {"_id": 0, "question": 1, "answer": 1, "timestamp": 1}
            ).sort("timestamp", -1).limit(limit))
        except PyMongoError as e:
            logger.error(f"Error al obtener historial: {e}")
            return []

mongodb = MongoDB()