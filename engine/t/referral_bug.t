use Test::More;
use lib "t/lib";

use MockResolver 'referral_bug', {multiple => 1};
# use MockBootstrap 'referral_bug', {multiple => 1};

use_ok( 'DNSCheck' );

my %tags;
my @res;

subtest referral_loop => sub {
    my $check = new DNSCheck( { configdir => './t/config' } );
    $check->add_fake_glue( 'test', 'a.ns.nic.test', '85.24.141.132' );
    $check->add_fake_glue( 'test', 'b.ns.nic.test', '85.24.141.132' );
    $check->delegation->test( 'test' );

    $res = $check->logger->export_hash;
    %tags = map { $_->{tag} => 1 } @$res;

    sub has {
        my ( $tag ) = @_;
        ok( $tags{$tag}, "has $tag" );
    }

    has( 'DELEGATION:GLUE_FOUND_AT_PARENT' );
    has( 'DELEGATION:GLUE_REFERRAL_FOLLOWED' );
    has( 'DELEGATION:GLUE_BROKEN_REFERRAL' );
};

subtest weird_but_ok => sub {
    my $check = new DNSCheck( { configdir => './t/config' } );
    $check->add_fake_glue( 'test', 'a.ns.nic2.test', '85.24.141.132' );
    $check->add_fake_glue( 'test', 'b.ns.nic2.test', '85.24.141.132' );
    $check->delegation->test( 'test' );

    $res = $check->logger->export_hash;
    %tags = map { $_->{tag} => 1 } @$res;

    sub has {
        my ( $tag ) = @_;
        ok( $tags{$tag}, "has $tag" );
    }

    has( 'DELEGATION:GLUE_FOUND_AT_PARENT' );
    has( 'DELEGATION:GLUE_FOUND_AT_CHILD' );
};

subtest weird_and_broken => sub {
    my $check = new DNSCheck( { configdir => './t/config' } );
    $check->add_fake_glue( 'test', 'a.ns.nic3.test', '85.24.141.132' );
    $check->add_fake_glue( 'test', 'b.ns.nic3.test', '85.24.141.132' );
    $check->delegation->test( 'test' );

    $res = $check->logger->export_hash;
    %tags = map { $_->{tag} => 1 } @$res;

    sub has {
        my ( $tag ) = @_;
        ok( $tags{$tag}, "has $tag" );
    }

    has( 'DELEGATION:GLUE_FOUND_AT_PARENT' );
    has( 'DELEGATION:GLUE_ERROR_AT_CHILD' );
};

subtest has_cname => sub {
    my $check = new DNSCheck( { configdir => './t/config' } );
    $check->add_fake_glue( 'test', 'a.ns.nic4.test', '85.24.141.132' );
    $check->add_fake_glue( 'test', 'b.ns.nic4.test', '85.24.141.132' );
    $check->delegation->test( 'test' );

    $res = $check->logger->export_hash;
    %tags = map { $_->{tag} => 1 } @$res;

    sub has {
        my ( $tag ) = @_;
        ok( $tags{$tag}, "has $tag" );
    }

    has( 'DELEGATION:GLUE_FOUND_AT_PARENT' );
    has( 'DELEGATION:CHILD_GLUE_CNAME' );
};

done_testing;
