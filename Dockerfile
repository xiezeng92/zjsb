FROM alpine:3.20
WORKDIR /app

RUN apk add --no-cache curl openssl tini

# 下载并准备原始脚本
RUN curl -Lo zjsb.sh "https://raw.githubusercontent.com/xiezeng92/zjsb/refs/heads/main/zjsb.sh" && chmod +x zjsb.sh

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["/bin/sh", "zjsb.sh"]
