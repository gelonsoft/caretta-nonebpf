FROM golang:1.21 as builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . /build/
ENV GOCACHE=/root/.cache/go-build
RUN --mount=type=cache,target="/root/.cache/go-build" CGO_ENABLED=0 GOOS=linux go build -o bin/caretta cmd/caretta/caretta.go

FROM alpine:3.19

WORKDIR /app
COPY --from=builder build/bin/caretta ./

VOLUME /sys/kernel/debug

CMD ./caretta