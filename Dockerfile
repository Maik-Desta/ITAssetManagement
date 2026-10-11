FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt "psycopg[binary]==3.2.3"
COPY itam ./itam
RUN useradd --system --uid 10001 itam && chown -R itam /app
USER itam
EXPOSE 8000
HEALTHCHECK CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8000/healthz')"
CMD ["uvicorn", "itam.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
