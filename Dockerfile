FROM golang:1.20

WORKDIR /app
COPY . .
RUN go mod tidy
RUN go mod download
RUN go build main.go

EXPOSE 8000
EXPOSE 8080