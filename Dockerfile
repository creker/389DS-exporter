FROM golang:1.17.2-alpine3.14 AS build

WORKDIR /go/src/

COPY ./ ./

ENV CGO_ENABLED=0

RUN go build -o /go/bin/389DS-exporter

FROM alpine:3.14

COPY --from=build /go/bin/389DS-exporter /usr/local/bin/389DS-exporter

EXPOSE 9313

ENTRYPOINT ["/usr/local/bin/389DS-exporter"]
