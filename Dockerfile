ARG TRIVY_VERSION=0.70.0
FROM aquasec/trivy:${TRIVY_VERSION} AS trivy

FROM python:3.14.5-slim

WORKDIR /app

COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
COPY pyproject.toml README.md ./
COPY src ./src
COPY tests ./tests
COPY fixtures ./fixtures

RUN pip install --no-cache-dir .

ENTRYPOINT ["vuln-report"]
