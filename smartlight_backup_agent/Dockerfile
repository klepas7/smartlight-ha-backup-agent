FROM ghcr.io/home-assistant/base:3.24

RUN apk add --no-cache \
    python3 \
    py3-pip \
    ca-certificates

WORKDIR /app

COPY app/requirements.txt /app/requirements.txt

RUN pip3 install --no-cache-dir --break-system-packages \
    -r /app/requirements.txt

COPY app/ /app/

COPY run.sh /run.sh
RUN chmod a+x /run.sh

CMD [ "/run.sh" ]
