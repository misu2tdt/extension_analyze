FROM mcr.microsoft.com/playwright/python:v1.40.0-jammy

WORKDIR /sandbox

# Cài thêm công cụ hệ thống
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        xvfb \
        tcpdump \
        curl \
        ca-certificates \
        unzip && \
    rm -rf /var/lib/apt/lists/*

# Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy code + honey pages
COPY . /sandbox/
RUN chmod +x /sandbox/entrypoint.sh

# Honeypot environment variables — nếu extension exfil các biến này,
# ta thấy chuỗi HONEYPOT trong outgoing traffic => bằng chứng malicious tuyệt đối
ENV OPENAI_API_KEY=sk-HONEYPOT-DO-NOT-USE-0000000000000000
ENV GITHUB_TOKEN=ghp_HONEYPOTDONOTUSE0000000000000000000000
ENV AWS_ACCESS_KEY_ID=AKIAHONEYPOT0000DONOTUSE
ENV AWS_SECRET_ACCESS_KEY=HONEYPOTsecretkeyDoNotUse0000000000000000

# Honeypot files — nếu extension đọc các file này => suspicious
RUN mkdir -p /root/.ssh /root/.aws && \
    printf -- "-----BEGIN HONEYPOT KEY-----\nHONEYPOT-DO-NOT-USE\n-----END HONEYPOT KEY-----\n" > /root/.ssh/id_rsa && \
    chmod 600 /root/.ssh/id_rsa && \
    printf "[default]\naws_access_key_id=AKIAHONEYPOT0000DONOTUSE\naws_secret_access_key=HONEYPOTsecretkeyDoNotUse\n" > /root/.aws/credentials

ENTRYPOINT ["/sandbox/entrypoint.sh"]