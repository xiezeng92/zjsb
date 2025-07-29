# Dockerfile (for original script)
FROM alpine:3.20
WORKDIR /app

RUN apk add --no-cache curl openssl 

# 下载并准备原始脚本
RUN curl -Lo zjsb.sh "https://raw.githubusercontent.com/xiezeng92/zjsb/refs/heads/main/zjsb.sh" && chmod +x zjsb.sh

ENTRYPOINT ["/app/zjsb.sh"]
CMD ["/app/sing-box", "run", "-c", "/app/sb.json"]
