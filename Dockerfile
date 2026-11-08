# Stage 1: Build React SPA Frontend
FROM node:20-alpine AS frontend-builder
WORKDIR /build
COPY frontend/package*.json ./
RUN npm ci --silent
COPY frontend/ ./
ENV VITE_API_BASE_URL=""
RUN npm run build

# Stage 2: Production Python Backend + Static Host
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app
COPY requirements.txt ./requirements.txt
RUN python -m pip install --upgrade pip && pip install -r requirements.txt
COPY . .
COPY --from=frontend-builder /build/dist /app/frontend/dist
RUN mkdir -p /app/data/chroma /app/data/sample_logs /app/data/knowledge
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
