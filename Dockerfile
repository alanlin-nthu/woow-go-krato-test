FROM golang:alpine

RUN apk add --no-cache git bash && \
  sed -i 's/bin\/ash/bin\/bash/g' /etc/passwd

# wait-for-it service is installed to wait for postgres service to start
ADD wait-for-it.sh /usr/local/bin

RUN chmod 755 /usr/local/bin/wait-for-it.sh

WORKDIR /src
COPY . /src

EXPOSE 4455

CMD go run main.go
