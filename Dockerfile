FROM python:3.11-slim

WORKDIR /app

COPY server.py .
COPY ledgerly/ ledgerly/

RUN pip install --no-cache-dir flask==3.0.3

EXPOSE 5001

CMD ["python3", "server.py", "run"]
