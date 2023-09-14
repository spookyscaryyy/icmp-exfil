PROG_S = send
PROG_R = recv

PROG_S_SRC = $(PROG_S)_src
PROG_R_SRC = $(PROG_R)_src

.PHONY: all send recv clean fmt vet

all:
	make $(PROG_S)
	make $(PROG_R)

send:
	$(MAKE) -C $(PROG_S_SRC)
	mv $(PROG_S_SRC)/$(PROG_S) .
	mv $(PROG_S_SRC)/$(PROG_S).exe .

recv:
	$(MAKE) -C $(PROG_R_SRC)
	mv $(PROG_R_SRC)/$(PROG_R) .
	mv $(PROG_R_SRC)/$(PROG_R).exe .

clean:
	rm -f $(PROG_S).exe
	rm -f $(PROG_R).exe
	rm -f $(PROG_S)
	rm -f $(PROG_R)

fmt:
	gofmt -w $(PROG_S_SRC)/$(PROG_S).go
	gofmt -w $(PROG_R_SRC)/$(PROG_R).go

vet:
	go vet $(PROG_S_SRC)/$(PROG_S).go
	go vet $(PROG_R_SRC)/$(PROG_R).go
