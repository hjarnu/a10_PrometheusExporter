FROM ubuntu:latest
RUN apt-get update --fix-missing && \
    apt-get install -y python3-pip python3 build-essential python3-venv && \
    rm -rf /var/lib/apt/lists/*
COPY . /app
WORKDIR /app
RUN python3 -m venv venv
RUN . venv/bin/activate && pip install --no-cache-dir -r requirements.txt
ENV PATH="/app/venv/bin:$PATH"
ENTRYPOINT ["python3"]
CMD ["acos_exporter.py"]
