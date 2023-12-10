FROM golang:1.19

WORKDIR /usr/src/app

ENV GOOS=linux
ENV CGO_ENABLED=0

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -ldflags '-w -s' -a -installsuffix cgo -o webserver main.go

FROM scratch

COPY --from=0 /usr/src/app/webserver webserver
COPY --from=0 /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

CMD ["./webserver"]