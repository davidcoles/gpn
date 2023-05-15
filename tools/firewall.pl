#!/usr/bin/perl
use strict;
use warnings;
use YAML;
use Getopt::Std;
use v5.10;
no warnings 'experimental';

my $PREFIX="10.123";

getopts("p:", \my %opt);

my $c = Load(join('', <>));

my %groups = %{$c->{'groups'}} if defined $c->{'groups'};
my @roles = @{$c->{'roles'}} if defined $c->{'roles'};
my %acls = %{$c->{'access-lists'}} if defined $c->{'access-lists'};
my %objs = %{$c->{'object-groups'}} if defined $c->{'object-groups'};


if(defined $opt{'p'}) {
    $PREFIX = $opt{'p'};
}

print "#!/bin/sh -e\n";
print "PREFIX=$PREFIX\n";
print "sysctl net.ipv4.ip_forward=0\n";
print <DATA>;
print ruleset();
print "iptables -A FORWARD -j main\n";
print "sysctl net.ipv4.ip_forward=1\n";
exit;


sub wildcard {
    my($s) = @_;
    return undef unless $s =~ /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/;
    my($a, $b, $c, $d) = ($1+0, $2+0, $3+0, $4+0);
    return undef if ($a > 255) || ($b > 255) || ($c > 255) || ($d > 255);
    return join(".", ~$a&0xff, ~$b&0xff, ~$c&0xff, ~$d&0xff);
}

sub source {
    my($type, $arg) = @_;
    return address($type, $arg, 0);
}

sub destination {
    my($type, $arg) = @_;
    return address($type, $arg, 1);
}

sub address {
    my($type, $arg, $d) = @_;
    my $x = $d ? "-d" : "-s";
    given($type) {
	when("any") { return ("$x 0.0.0.0/0") }
	when("host") { return ("$x $arg") }
	when("object-group") {
	    die "obj: $arg" if !exists $objs{$arg};
	    if($d) {
		return ("-m set --match-set HOST_$arg dst")
	    }
	    return ("-m set --match-set HOST_$arg src");
	    return map { "$x $_" } @{$objs{$arg}};
	}
	when(/^\d+\.\d+\.\d+\.\d+$/) {
	    my $mask = wildcard($arg);
	    die unless defined $mask;
	    return ("$x $type/$mask");
	}
    }
    die "$x $type $arg";
}

sub port {
    my($p) = @_;
    given($p) {
	when(/^\d+$/) {}
	when("domain") { $p = 53 }
	when("www") { $p = 80 }
	when("ftp") { $p = 21 }
	default { die "Unknown port: $p\n" }
    }
    return $p;
}

sub l4 {
    my($op, @l) = @_;
    die "no args to op" if !scalar(@l);
    given($op) {
	when("eq")  { return (map { port($_) } @l) }
	#when("neq") { return ('!', map { port($_) } @l) } # need a sub-rule with list of port/RETURN rules and defualt as action
	when("gt")  {
	    die "too many args" unless scalar(@l) == 1;
	    return (port($l[0]).":");
	}
	when("lt")  {
	    die "too many args" unless scalar(@l) == 1;
	    return (":".port($l[0]));
	}
	when("range")  {
	    die "wrong args" unless scalar(@l) == 2;
	    return (port($l[0]).":".port($l[1]));
	}
    }
    die "unknown op: $op";
}

sub arguments {
    my($p, @a) = @_;

    given($p) {
	when("ip") {
	    die "ip args not supported" unless scalar(@a) == 0;
	    return ("");
	}
	when (/^(tcp|udp)$/) {
	    return ("-m $p -p $p", "") if !scalar(@a);	    
	    my(@r) = l4(@a);
	    return ("-m $p -p $p --dport", @r);
	}


	when("icmp") {
	    #die;
	    return ("-p icmp", "") if !scalar(@a);
	    my @r;
	    foreach my $i (@a) {
		given($i) {
		    when("echo") {
			push(@r, 'echo-request');
		    }
		    when("echo-reply") {
			push(@r, 'echo-reply');
		    }
		    default { die "Unknown ICMP: $i"
		    }
		}
	    }
	    return ('-p icmp --icmp-type', @r);
	}
    }
    die "unknown protocol: $p @a";
}

sub access_lists {

    my @rules;
    
    foreach my $acl (sort keys %acls) {
	
	push @rules, "iptables -N ACL_$acl\n";

	my $v = $acls{$acl};

	foreach my $s (@$v) {
	    my $S = $s;
	    if($s =~ m:^(permit|deny)\s+(ip|tcp|udp|icmp)\s+(any|\S+\s+\S+)\s+(any|\S+\s+\S+)(|\s+\S.*)$:) {

		my $action = $1;
		my $protocol = $2;
		my $source = $3;
		my $destination = $4;
		my $arguments = $5;
		
		my @source = split(/\s+/, $source);
		my @destination = split(/\s+/, $destination);
		
		$arguments =~ s/^\s+//;
		$arguments =~ s/\s+$//;
		
		my @a = split(/\s+/, $arguments);
		my $a = join(",", @a);
		
		#warn "$protocol | @source | @destination |$a\n";
		
		my @s = source(@source);           # address(@source, 0);
		my @d = destination(@destination); # address(@destination, 1);
		my($m, @p) = arguments($protocol, @a);
		my $act = $action eq 'permit' ? 'ACCEPT' : 'LOG_REJECT';
		
			    
		foreach my $s (@s) {	    
		    foreach my $d (@d) {
			if(scalar(@p) > 0) {
			    foreach my $p (@p) {
				push @rules, "iptables -A ACL_$acl $s $d $m $p -j $act";
			    }
			} else {
			    push @rules, "iptables -A ACL_$acl $s $d $m -j $act";
			}
		    }
		}
	    } else {
		die "$s";
	    }
	}
    }

    return @rules;
}

sub ruleset {
    my @ret;
    
    foreach my $n (keys %objs) {
	
	push @ret, "ipset -exist destroy HOST_${n}\n";
	push @ret, "ipset -exist create HOST_${n} hash:net\n";
	
	foreach my $o (@{$objs{$n}}) {
	    given($o) {
		when(m:^\d+\.\d+\.\d+\.\d+$:) {}
		when(m:^\d+\.\d+\.\d+\.\d+/\d+$:) {}
		default { die "Not an IP or CIDR: '$o'\n" }
	    }
	    
	    push @ret, "ipset -exist add HOST_${n} $o\n";
	}
    }
       
    foreach(access_lists()) {
	push @ret, "$_\n";
    }
    
    if(exists($acls{'ALL'})) {
	push @ret, "iptables -I vpn -j ACL_ALL\n";
    }
    
    
    foreach my $e (@roles) {
	my $n = $e->{"role"};
	my $a = $e->{"acls"};    
	
	push @ret, "ipset -exist create ROLE_${n} hash:ip timeout 300\n";
	push @ret, "iptables -N ROLE_$n\n";
	push @ret, "iptables -A vpn -m set --match-set ROLE_${n} src -j ROLE_$n\n";
	
	foreach my $r (@$a) {
	    push @ret, "iptables -A ROLE_$n -j ACL_$r\n";	
	}
    }

    return @ret;
}


__END__;
iptables -F
iptables -X

iptables -N LOG_DROP
iptables -A LOG_DROP -j LOG --log-prefix "FORWARD:DROP:" --log-level 6
#iptables -A LOG_DROP -j DROP
    
iptables -N LOG_REJECT
iptables -A LOG_REJECT -j LOG --log-prefix "FORWARD:REJECT:" --log-level 6
#iptables -A LOG_REJECT -j REJECT
    
iptables -N vpn

iptables -N main
iptables -A main -m state --state ESTABLISHED,RELATED -j ACCEPT

iptables -A main -s $PREFIX.0.0/16 -j vpn    
iptables -A main -j LOG_REJECT

iptables -A INPUT  -s $PREFIX.0.0/16 -d $PREFIX.0.0 -m tcp -p tcp --dport 8443 -j ACCEPT # beacon
iptables -A OUTPUT -d $PREFIX.0.0/16 -s $PREFIX.0.0 -m tcp -p tcp --sport 8443 -j ACCEPT # beacon   
#iptables -A INPUT  -s $PREFIX.255.0/24 -j ACCEPT # Reserve top /24 for VMs running daemon/routing
#iptables -A OUTPUT -d $PREFIX.255.0/24 -j ACCEPT # Reserve top /24 for VMs running daemon/routing
iptables -A INPUT  -s $PREFIX.0.0/16 -j DROP
iptables -A OUTPUT -d $PREFIX.0.0/16 -j DROP
    
iptables -P FORWARD DROP
