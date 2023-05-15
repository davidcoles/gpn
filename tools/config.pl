#!/usr/bin/perl
use strict;
use YAML;
use JSON;

my $conf = YAML::Load(join('', <>));

$conf->{'loglevel'} += 0;
$conf->{'oauth2'}->{'expirydelta'} += 0;
$conf->{'wireguard'}->{'keepalive'} += 0;
$conf->{'wireguard'}->{'port'} += 0;

print to_json($conf, {pretty => 1, canonical => 1});
