FROM python:3.12 AS python

ENV PYTHONUNBUFFERED=1

ARG APPROOT=/app

WORKDIR ${APPROOT}

ENV PYTHONPATH=${APPROOT}

RUN apt-get update && apt-get install -y \
build-essential \
libpq-dev \
&& rm -rf /var/lib/apt/lists/*

COPY ./requirements.txt ${APPROOT}/

RUN pip install --upgrade pip && pip install -r requirements.txt

COPY ./pyproject.toml ./entrypoint.sh ${APPROOT}/

COPY ./app ${APPROOT}/app

COPY ./data ${APPROOT}/data

ENTRYPOINT [ "/app/entrypoint.sh" ]

CMD ["fastapi", "run", "--workers", "4", "app/main.py"]
