FROM python:3.9-slim
WORKDIR /app
COPY . .
RUN pip install --no-cache-dir paho-mqtt requests
RUN pip install -r ./script2/requirements.txt
RUN apt update -y && apt upgrade -y
CMD ["python", "gateway.py"]
