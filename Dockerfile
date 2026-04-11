FROM postgres:alpine

# переменные окружения
ENV POSTGRES_USER=postgres
ENV POSTGRES_PASSWORD=postgres
ENV POSTGRES_DB=cvedb

# копируем схему
COPY schema.sql /docker-entrypoint-initdb.d/schema.sql