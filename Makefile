.PHONY: test all test-race lint clean bench

all: lint clean test test-race bench

test:
	go test -count=1 -v ./...

test-race:
	go test -race -count=1 -v ./...

bench:
	go test -bench=. -benchmem ./...

lint:
	go vet ./...

clean:
	go clean ./...