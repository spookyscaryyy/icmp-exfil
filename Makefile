PROGRAM = exfil
SOURCE = *.go

.PHONY: build clean fmt vet

build:
	CGO_ENABLED=0 go build -o $(PROGRAM) $(SOURCE)

clean:
	rm -f $(PROGRAM)

fmt:
	gofmt -w $(SOURCE)

vet:
	go vet $(SOURCE)
