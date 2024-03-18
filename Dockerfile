FROM golang:1.21
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . /build/
RUN CGO_ENABLED=0 GOOS=linux go build -o bin/caretta cmd/caretta/caretta.go

FROM alpine:3.19

WORKDIR /app
COPY --from=builder build/bin/caretta ./

VOLUME /sys/kernel/debug

CMD ./caretta