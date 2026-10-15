FROM python:3.12-slim

WORKDIR /repo

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/repo/backend

# Install dependencies first for better layer caching
COPY backend/requirements.txt /repo/backend/requirements.txt
RUN pip install --no-cache-dir -r /repo/backend/requirements.txt

# Mirror the repository layout so relative ML/model paths behave identically
COPY backend/app /repo/backend/app
COPY ml /repo/ml
COPY scripts /repo/scripts

EXPOSE 8000

CMD ["/bin/sh", "-c", "python /repo/scripts/entrypoint.py && exec uvicorn app.main:app --host 0.0.0.0 --port 8000"]
