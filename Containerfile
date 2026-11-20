FROM docker.io/kalilinux/kali-rolling:latest

LABEL description="n3rve - WPA/WPA2 passphrase recovery"

ENV DEBIAN_FRONTEND=noninteractive \
    HANDSHAKE_NO_AUTOINSTALL=1 \
    PYTHONUNBUFFERED=1 \
    PIP_BREAK_SYSTEM_PACKAGES=1

RUN apt-get update && apt-get install -y --no-install-recommends \
        hashcat \
        aircrack-ng \
        hcxtools \
        python3 \
        python3-pip \
        python3-venv \
        python3-setuptools \
        git \
        ca-certificates \
        intel-opencl-icd \
        mesa-opencl-icd \
        ocl-icd-libopencl1 \
        wordlists \
    && if [ -f /usr/share/wordlists/rockyou.txt.gz ]; then gunzip -f /usr/share/wordlists/rockyou.txt.gz; fi \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work

COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

COPY . /work

ENV PATH="/work/bin:${PATH}"

CMD ["python3", "main.py"]
