PROGRAM = send
SOURCE = *.go

build:
	CGO_ENABLED=0 go build -o $(PROGRAM) $(SOURCE)
	GOOS=windows GOARCH=386 go build -o $(PROGRAM).exe $(SOURCE)

clean:
	rm -f $(PROGRAM).exe
	rm -f $(PROGRAM)

fmt:
	gofmt -w $(SOURCE)

vet:
	go vet $(SOURCE)
