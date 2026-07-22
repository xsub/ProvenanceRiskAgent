FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PROVENANCE_AGENT_DB=/data/provenance-agent.sqlite3

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src
COPY examples ./examples
COPY eval ./eval

RUN pip install --no-cache-dir '.[live]'

EXPOSE 8080

CMD ["uvicorn", "provenance_agent.api:app", "--host", "0.0.0.0", "--port", "8080"]
