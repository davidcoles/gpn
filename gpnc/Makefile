
all: gpnc

clean:
	rm -f gpnc

# Override these on the command line to build for your environment, eg.:
# make ROOTCA=MyCorpCA NAME=MyCorpVPN DOMAIN=vpn.mycorpdomain.com

NAME 	?= ExampleVPN
ROOTCA 	?= ExampleCA
DOMAIN 	?= vpn.example.com
SERVICE ?= $(DOMAIN)

FLAGS = -X main.NAME=$(NAME) \
	-X main.ROOTCA=$(ROOTCA) \
	-X main.DOMAIN=$(DOMAIN) \

gpnc: gpnc.go
	go build -ldflags "$(FLAGS)" -o $@ $<
