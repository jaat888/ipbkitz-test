FROM python:3.12-slim
WORKDIR /app
COPY . .
ENV PORT=7700
EXPOSE 7700
CMD ["python3", "-u", "app.py"]
