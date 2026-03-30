use strict;
use warnings;
use Test::More tests => 29;
use lib 't';
use MockUA;
use HTTP::Request;
use URI;

use_ok('WWW::Shodan::API');

my $KEY    = 'TESTKEY123';
my $shodan = WWW::Shodan::API->new($KEY);
my $mock   = MockUA->new();
$shodan->{UA} = $mock;

# --- GET request puts key + params in query string ---
$mock->set_response(200, '{"plan":"dev","query_credits":100,"scan_credits":100,"https":1,"unlocked":1,"unlocked_left":100,"telnet":1}');
my $result = $shodan->api_info();
my $req = $mock->last_request();
ok($req, 'api_info made a request');
is($req->method, 'GET', 'api_info uses GET');
like($req->uri, qr{/api-info}, 'api_info hits /api-info');
like($req->uri, qr{key=TESTKEY123}, 'api_info sends API key');
is($result->{plan}, 'dev', 'api_info returns decoded JSON');

# --- GET with query params ---
$mock->set_response(200, '{"8.8.8.8":"dns.google"}');
$shodan->resolve_dns(['8.8.8.8']);
$req = $mock->last_request();
is($req->method, 'GET', 'resolve_dns uses GET');
like($req->uri, qr{/dns/resolve}, 'resolve_dns hits correct path');
like($req->uri, qr{hostnames=8\.8\.8\.8}, 'resolve_dns sends hostnames param');

# --- Error handling: HTTP error ---
$mock->set_response(401, '{"error":"Invalid API key"}');
eval { $shodan->api_info() };
like($@, qr/Invalid API key/, 'croak on API error with error message');

# --- Error handling: non-JSON response ---
$mock->set_response(500, 'Internal Server Error');
eval { $shodan->api_info() };
like($@, qr/500/, 'croak on HTTP 500 error');

# --- my_ip returns scalar string ---
$mock->set_response(200, '"1.2.3.4"');
my $ip = $shodan->my_ip();
is($ip, '1.2.3.4', 'my_ip returns IP string');

# --- host_ip ---
$mock->set_response(200, '{"ip_str":"8.8.8.8","ports":[53,443]}');
$result = $shodan->host_ip({ IP => '8.8.8.8' });
$req = $mock->last_request();
is($req->method, 'GET', 'host_ip uses GET');
like($req->uri, qr{/shodan/host/8\.8\.8\.8}, 'host_ip puts IP in path');
like($req->uri, qr{key=TESTKEY123}, 'host_ip sends API key');
is($result->{ip_str}, '8.8.8.8', 'host_ip returns decoded data');

$mock->set_response(200, '{"ip_str":"8.8.8.8","ports":[53]}');
$shodan->host_ip({ IP => '8.8.8.8', HISTORY => 1, MINIFY => 1 });
$req = $mock->last_request();
like($req->uri, qr{history=true}, 'host_ip sends history param');
like($req->uri, qr{minify=true}, 'host_ip sends minify param');

# --- search ---
$mock->set_response(200, '{"total":1,"matches":[]}');
$result = $shodan->search({ port => 80 }, [], {});
$req = $mock->last_request();
is($req->method, 'GET', 'search uses GET');
like($req->uri, qr{/shodan/host/search}, 'search hits correct path');

# --- count ---
$mock->set_response(200, '{"total":42}');
$result = $shodan->count({ port => 80 }, []);
$req = $mock->last_request();
is($req->method, 'GET', 'count uses GET');
like($req->uri, qr{/shodan/host/count}, 'count hits correct path');

# --- tokens ---
$mock->set_response(200, '{"attributes":{},"errors":[],"filters":[],"string":"apache"}');
$result = $shodan->tokens({ product => 'apache' });
$req = $mock->last_request();
is($req->method, 'GET', 'tokens uses GET');
like($req->uri, qr{/shodan/host/search/tokens}, 'tokens hits correct path');

# --- services ---
$mock->set_response(200, '{"80":"http","443":"https"}');
$result = $shodan->services();
$req = $mock->last_request();
is($req->method, 'GET', 'services uses GET');
like($req->uri, qr{/shodan/services}, 'services hits correct path');

# --- reverse_dns ---
$mock->set_response(200, '{"8.8.8.8":["dns.google"]}');
$shodan->reverse_dns(['8.8.8.8']);
$req = $mock->last_request();
is($req->method, 'GET', 'reverse_dns uses GET');
like($req->uri, qr{/dns/reverse}, 'reverse_dns hits correct path');
like($req->uri, qr{ips=8\.8\.8\.8}, 'reverse_dns sends ips param');
