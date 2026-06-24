FROM golang:1.22-alpine AS build

WORKDIR /src
RUN apk add --no-cache ca-certificates
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/potpuri ./cmd/potpuri

FROM alpine:3.20

RUN adduser -D -H -u 10001 potpuri && apk add --no-cache ca-certificates
USER potpuri
WORKDIR /app
COPY --from=build /out/potpuri /app/potpuri
EXPOSE 8080
ENTRYPOINT ["/app/potpuri"]
