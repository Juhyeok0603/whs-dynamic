FROM python:3.12-slim
RUN useradd --create-home --uid 10001 analyzer
USER analyzer
WORKDIR /workspace
ENTRYPOINT ["python"]
