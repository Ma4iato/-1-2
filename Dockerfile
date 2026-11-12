FROM python:3.11-slim

RUN useradd --create-home --shell /bin/bash appuser
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src ./src
RUN chown -R appuser:appuser /app

USER appuser
ENV FLASK_APP=src/app.py
EXPOSE 5000

CMD ["sh", "-c", "python src/db.py && flask run --host=0.0.0.0 --port=5000"]
