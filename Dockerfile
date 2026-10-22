FROM python:3.12-slim

WORKDIR /app

# server.py uses only the Python standard library, so there is nothing to pip install.
COPY server.py index.html ./

ENV HOST=0.0.0.0 \
    PORT=8000 \
    PYTHONUNBUFFERED=1

EXPOSE 8000

CMD ["python", "server.py"]
