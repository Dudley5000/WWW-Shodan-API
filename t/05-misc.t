use strict;
use warnings;
use Test::More tests => 25;
use lib 't';
use MockUA;

use WWW::Shodan::API;

my $KEY    = 'TESTKEY123';
my $shodan = WWW::Shodan::API->new($KEY);
my $mock   = MockUA->new();
$shodan->{UA} = $mock;

# --- queries ---
$mock->set_response(200, '{"matches":[{"title":"Apache"}],"total":1}');
my $result = $shodan->queries();
my $req = $mock->last_request();
is($req->method, 'GET', 'queries uses GET');
like($req->uri, qr{/shodan/query(?:[?]|$)}, 'queries hits /shodan/query');
like($req->uri, qr{key=TESTKEY123}, 'queries sends API key');

$mock->set_response(200, '{"matches":[],"total":0}');
$shodan->queries({ page => 2, sort => 'votes', order => 'desc' });
$req = $mock->last_request();
like($req->uri, qr{page=2}, 'queries sends page param');
like($req->uri, qr{sort=votes}, 'queries sends sort param');
like($req->uri, qr{order=desc}, 'queries sends order param');

# --- search_queries ---
$mock->set_response(200, '{"matches":[{"title":"Apache"}],"total":1}');
$result = $shodan->search_queries({ query => 'apache' });
$req = $mock->last_request();
is($req->method, 'GET', 'search_queries uses GET');
like($req->uri, qr{/shodan/query/search}, 'search_queries hits correct path');
like($req->uri, qr{query=apache}, 'search_queries sends query param');

# --- query_tags ---
$mock->set_response(200, '{"matches":[{"value":"ics","count":100}],"total":1}');
$result = $shodan->query_tags();
$req = $mock->last_request();
is($req->method, 'GET', 'query_tags uses GET');
like($req->uri, qr{/shodan/query/tags}, 'query_tags hits correct path');

$mock->set_response(200, '{"matches":[],"total":0}');
$shodan->query_tags({ size => 5 });
$req = $mock->last_request();
like($req->uri, qr{size=5}, 'query_tags sends size param');

# --- profile ---
$mock->set_response(200, '{"member":true,"credits":{"scan":0,"query":100},"display_name":"Test"}');
$result = $shodan->profile();
$req = $mock->last_request();
is($req->method, 'GET', 'profile uses GET');
like($req->uri, qr{/account/profile}, 'profile hits correct path');
is($result->{display_name}, 'Test', 'profile returns decoded data');

# --- domain_info (plain string) ---
$mock->set_response(200, '{"domain":"google.com","subdomains":["www","mail"],"tags":[],"data":[]}');
$result = $shodan->domain_info('google.com');
$req = $mock->last_request();
is($req->method, 'GET', 'domain_info uses GET');
like($req->uri, qr{/dns/domain/google\.com}, 'domain_info (string) puts domain in path');
is($result->{domain}, 'google.com', 'domain_info returns decoded data');

# --- domain_info (hashref with options) ---
$mock->set_response(200, '{"domain":"google.com","subdomains":[],"tags":[],"data":[]}');
$shodan->domain_info({ domain => 'google.com', history => 1, type => 'A' });
$req = $mock->last_request();
like($req->uri, qr{/dns/domain/google\.com}, 'domain_info (hashref) puts domain in path');
like($req->uri, qr{history=1}, 'domain_info sends history param');
like($req->uri, qr{type=A}, 'domain_info sends type param');

# --- http_headers ---
$mock->set_response(200, '{"Host":"api.shodan.io","User-Agent":"test"}');
$result = $shodan->http_headers();
$req = $mock->last_request();
is($req->method, 'GET', 'http_headers uses GET');
like($req->uri, qr{/tools/httpheaders}, 'http_headers hits correct path');

# --- regression: existing methods still work ---
$mock->set_response(200, '{"plan":"dev","query_credits":100}');
$result = $shodan->api_info();
ok($result, 'api_info still works');

$mock->set_response(200, '{"total":1,"matches":[]}');
$result = $shodan->search({ port => 443 }, [], {});
ok($result, 'search still works');
