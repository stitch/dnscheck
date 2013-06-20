#!/usr/bin/perl -sw
#
# $Id$

require 5.008;
use warnings;
use strict;

use Test::More;
use lib "t/lib";
use Net::IP;
use MockResolver 'asn';
# use MockBootstrap 'asn';
use DNSCheck;

######################################################################

my $check = new_ok('DNSCheck'  => [{configdir => './t/config'}]);

######################################################################

my ($tmp) = $check->asn->asdata("195.47.254.1");
is_deeply($tmp->[0],["47698"], 'Expected AS list');
isa_ok($tmp->[1], 'Net::IP');
is($tmp->[1]->ip, '195.47.254.0');

ok(!$check->asn->asdata('gurksallad'), 'No response for bogus IP');
is_deeply([$check->asn->asdata('192.168.12.12')], [], 'IPv4 not announced');

is_deeply(($check->asn->asdata('2a00:801:f0:211::152'))[0][0][0], 1257, 'IPv6 announced');
is_deeply([$check->asn->asdata('3a00:801:f0:211::152')], [], 'IPv6 not announced');


my %tag = map {$_->[3] => 1} @{$check->logger->export};

foreach my $tag (qw[ASN:INVALID_ADDRESS ASN:NOT_ANNOUNCE ASN:ANNOUNCE_BY ASN:ANNOUNCE_IN ]) {
    ok($tag{$tag}, "Has $tag");
}

my $asn = $check->asn;
is($asn->parent,$check);
$asn->flush;
ok(!$asn->{asn}, 'Cache correctly flushed');

eval {
    my $i = Net::IP->new('::1');
    $i->{ipversion} = 5;
    $tmp = $asn->asdata($i);
};
like($@, qr|Strange IP version: |, 'strange IP version');

$check->logger->clear;
$asn->{v4roots} = [];
$asn->{v6roots} = [];
$asn->asdata('195.47.254.17');
is(scalar(grep {$_->[3] eq 'ASN:LOOKUP_ERROR'} @{$check->logger->export}), 1, 'ASN:LOOKUP_ERROR');

done_testing();
