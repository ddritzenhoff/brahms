ARG GO_VERSION=1.20

FROM golang:${GO_VERSION}-alpine AS build
RUN apk --no-cache add ca-certificates
RUN addgroup -S gossip \
    && adduser -S -u 10000 -g gossip gossip

WORKDIR /src
COPY ./go.mod ./go.sum ./
RUN go mod download

COPY ./ ./

RUN CGO_ENABLED=0 go build -installsuffix 'static' -o /app ./cmd/gossip


FROM scratch AS final
COPY --from=build /app app
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=0 /etc/passwd /etc/passwd
USER gossip

ENTRYPOINT ["/app"]