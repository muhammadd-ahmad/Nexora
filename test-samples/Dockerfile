# Deliberately weak training sample. Do not build or deploy it.
FROM ubuntu:latest
ENV API_KEY=DEMO_ONLY_NOT_A_REAL_SECRET
RUN curl -fsSL https://example.invalid/install.sh | bash
# No USER instruction: left intentionally for the static checker.
