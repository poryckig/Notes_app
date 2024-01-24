FROM python:3.9.13-alpine

RUN pip install --upgrade pip

ENV PYTHONUNBUFFERED 1

RUN adduser -D worker
USER worker
WORKDIR /home/worker

COPY --chown=worker:worker requirements.txt requirements.txt
RUN python -m pip install --user -r requirements.txt

COPY --chown=worker:worker . .
