test:
	@go run cmd/main.go google.com

build:
	@go build -o $GOPATH/bin/dlook
