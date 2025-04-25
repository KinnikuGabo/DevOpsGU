FROM python:3.9-slim

WORKDIR /app

# Instalar dependencias del sistema para PDF y FAISS
RUN apt-get update && \
    apt-get install -y gcc python3-dev && \
    rm -rf /var/lib/apt/lists/*

# Crear directorio para uploads
RUN mkdir -p /app/uploads

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
