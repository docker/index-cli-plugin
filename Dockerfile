# build stage
FROM golang:1.19-alpine3.16@sha256:0eb08c89ab1b0c638a9fe2780f7ae3ab18f6ecda2c76b908e09eb8073912045d as build

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
