# NOTE: base image kept as python:3.13-slim (NOT ghcr.io/astral-sh/uv) — ghcr.io is
# unreliable from CN networks (see README troubleshooting); uv is pip-installed instead.
FROM python:3.13-slim-bookworm

ENV PYTHONUNBUFFERED=1
ENV TZ=Asia/Shanghai
RUN pip install --no-cache-dir uv

COPY ./skidc/pyproject.toml /skidc/pyproject.toml
COPY ./skidc/uv.lock /skidc/uv.lock
WORKDIR /skidc
RUN uv sync --frozen --no-install-project -i https://mirrors.aliyun.com/pypi/simple/

COPY ./skidc /skidc
RUN uv sync --frozen -i https://mirrors.aliyun.com/pypi/simple/
