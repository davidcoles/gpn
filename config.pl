#!/usr/bin/perl
use strict;
use YAML;
use JSON;

my $conf = YAML::Load(join('', <>));
print to_json($conf, {pretty => 1, canonical => 1});
