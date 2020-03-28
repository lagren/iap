.PHONY: test deps

deps:
	go get

test:
	go test ./...