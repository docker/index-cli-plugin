# build stage
FROM golang:1.20-alpine3.17 as build

RUN apk add --no-cache git build-base ca-certificates

WORKDIR /app

COPY go.mod ./
COPY go.sum ./

RUN go mod download

COPY . ./

# RUN go test
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -trimpath -o index-cli-plugin ./cmd/docker-index

# runtime stage
FROM scratch

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /app/index-cli-plugin /index-cli-plugin

ENTRYPOINT ["/index-cli-plugin"]
CMD ["--help"]
