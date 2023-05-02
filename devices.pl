#!/usr/bin/perl
use strict;
use YAML;
use JSON;

my $conf = YAML::Load(join('', <>));

my %devices;
my %numbers;
my %pubkeys;
my $nonum;


foreach (@$conf) {
    my $device = $_->{'device'};
    my $number = $_->{'number'}+0;
    my $pubkey = defined $_->{'pubkey'} ? $_->{'pubkey'} : "";
    my $admin  = $_->{'admin'} =~ /^\s*(yes|true|on)\s*$/i;

    if($number == 0) {
	$nonum = $device;
	next;
    }

    die "Entry with no device name appears. Yuck!\n" unless defined $device && $device ne "";
    die "Device $device occurs more than once!\n" if exists $devices{$device};
    die "Device $device has pubkey $pubkey which occurs more than once!\n" if exists $pubkeys{$pubkey};
    die "Device $device has number $number which occurs more than once!\n" if exists $numbers{$number};    
    die "Device $device has number $number out of range (1-65000)\n" if $number < 1 || $number > 65000;
    die "Device $device has invalid pubkey: '$pubkey'\n" if $pubkey ne "none" && length($pubkey) != 44;

    $pubkey = "" if $pubkey eq "none";
    
    $devices{$device} = {'index' => $number+0, 'pubkey' => $pubkey};
    $numbers{$number} = 1;
    $pubkeys{$pubkey} = 1 if $pubkey ne "";

    warn "WARNING: Device $device has no pubkey!\n" if $pubkey eq "";
}

if(defined($nonum)) {
    foreach(1..65000) {
	die "Device $nonum has no number - $_ is the first free one\n" unless defined $numbers{$_};
    }
    die "Device $nonum has no number an none seem free!\n";
}

my $output = {"serial"=> time(), "devices" => \%devices};
print to_json($output, {pretty => 1, canonical => 1});
