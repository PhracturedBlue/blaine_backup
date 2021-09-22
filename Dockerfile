FROM python:slim-bullseye

ARG UID=1000
ARG GID=1000
RUN apt-get update -y && \
    apt-get install -y dc3dd par2 sqlite3 && \
    apt-get clean -y && \
    rm -rf /var/lib/apt/lists/* /tmp/* /src

RUN addgroup --gid $GID debian && adduser --system --uid $UID --gid 1000 debian

ARG TEST
RUN if [ "$TEST" != "" ]; then pip install pytest pylint coverage pytest-cov; fi

RUN mkdir /work && chown debian:debian /work

USER debian

WORKDIR /work

CMD ["bash"]

