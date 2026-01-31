FROM python:3.11-slim

LABEL maintainer="Sergey Gladkovskiy <smgladkovskiy@gmail.com>"
LABEL description="UGOS Auth Proxy - PAM-based authentication for authentik SSO"
LABEL org.opencontainers.image.source="https://github.com/smgladkovskiy/ugos-auth-proxy"
LABEL org.opencontainers.image.licenses="MIT"

WORKDIR /app

# Copy the application
COPY main.py .

# Environment
ENV PORT=8080
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')" || exit 1

# Run as root (required for /etc/shadow access)
CMD ["python3", "main.py"]
