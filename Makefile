build:
	go mod tidy
	CGO_ENABLED=0 go build -buildmode pie
