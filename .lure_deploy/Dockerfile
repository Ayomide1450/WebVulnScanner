FROM python:3.12-slim
WORKDIR /app
COPY lure_app.py .
RUN pip install --no-cache-dir flask
EXPOSE 8000
CMD ["python", "lure_app.py"]
