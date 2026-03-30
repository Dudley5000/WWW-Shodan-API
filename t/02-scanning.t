use strict;
use warnings;
use Test::More tests => 24;
use lib 't';
use MockUA;

use WWW::Shodan::API;

my $KEY    = 'TESTKEY123';
my $shodan = WWW::Shodan::API->new($KEY);
my $mock   = MockUA->new();
$shodan->{UA} = $mock;

# --- search_facets ---
$mock->set_response(200, '["ip","port","org","isp"]');
my $result = $shodan->search_facets();
my $req = $mock->last_request();
is($req->method, 'GET', 'search_facets uses GET');
like($req->uri, qr{/shodan/host/search/facets}, 'search_facets hits correct path');
like($req->uri, qr{key=TESTKEY123}, 'search_facets sends API key');
is(ref $result, 'ARRAY', 'search_facets returns array');

# --- search_filters ---
$mock->set_response(200, '["port","org","asn","city"]');
$result = $shodan->search_filters();
$req = $mock->last_request();
is($req->method, 'GET', 'search_filters uses GET');
like($req->uri, qr{/shodan/host/search/filters}, 'search_filters hits correct path');

# --- ports ---
$mock->set_response(200, '[80,443,22,21]');
$result = $shodan->ports();
$req = $mock->last_request();
is($req->method, 'GET', 'ports uses GET');
like($req->uri, qr{/shodan/ports}, 'ports hits correct path');

# --- protocols ---
$mock->set_response(200, '{"http":"HTTP Banner Grabbing","https":"HTTPS"}');
$result = $shodan->protocols();
$req = $mock->last_request();
is($req->method, 'GET', 'protocols uses GET');
like($req->uri, qr{/shodan/protocols}, 'protocols hits correct path');

# --- scan (POST form-encoded) ---
$mock->set_response(200, '{"id":"SCAN1","count":2,"credits_left":90}');
$result = $shodan->scan(['1.2.3.4', '5.6.7.0/24']);
$req = $mock->last_request();
is($req->method, 'POST', 'scan uses POST');
like($req->uri, qr{/shodan/scan}, 'scan hits correct path');
is($req->header('Content-Type'), 'application/x-www-form-urlencoded', 'scan sends form body');
like($req->content, qr{ips=}, 'scan sends ips in body');
like($req->content, qr{1\.2\.3\.4}, 'scan body contains first IP');
is($result->{id}, 'SCAN1', 'scan returns decoded response');

# --- scan_internet (POST form-encoded) ---
$mock->set_response(200, '{"id":"SCAN2"}');
$result = $shodan->scan_internet({ port => 80, protocol => 'http' });
$req = $mock->last_request();
is($req->method, 'POST', 'scan_internet uses POST');
like($req->uri, qr{/shodan/scan/internet}, 'scan_internet hits correct path');
like($req->content, qr{port=80}, 'scan_internet sends port in body');
like($req->content, qr{protocol=http}, 'scan_internet sends protocol in body');

# --- scans ---
$mock->set_response(200, '{"matches":[{"id":"SCAN1","status":"DONE"}],"total":1}');
$result = $shodan->scans();
$req = $mock->last_request();
is($req->method, 'GET', 'scans uses GET');
like($req->uri, qr{/shodan/scans}, 'scans hits correct path');

# --- scan_status ---
$mock->set_response(200, '{"id":"SCAN1","status":"PROCESSING","count":1}');
$result = $shodan->scan_status('SCAN1');
$req = $mock->last_request();
is($req->method, 'GET', 'scan_status uses GET');
like($req->uri, qr{/shodan/scan/SCAN1}, 'scan_status puts ID in path');
