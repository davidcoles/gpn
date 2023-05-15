
all: gpn config.json devices.json

gpn: gpn.go */*.go static/*
	go build -o $@ gpn.go

clean:
	rm -f gpn config.json devices.json

#yq -o json $< >$@- && mv $@- $@
config.json: config.yaml
	tools/config.pl $< >$@- && mv $@- $@

devices.json: devices.yaml
	tools/devices.pl devices.yaml >$@- && mv $@- $@


# sudo apt install libyaml-perl libjson-perl golang-1.18
