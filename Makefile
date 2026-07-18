.PHONY: build test run tidy docker docker-up clean

APP := grok-auth-proxy
CMD := ./cmd/proxy

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/$(APP) $(CMD)

test:
	go test ./...

tidy:
	go mod tidy

run: build
	./bin/$(APP)

docker:
	docker build -t $(APP):local .

docker-up:
	docker compose up --build -d

clean:
	rm -rf bin/
