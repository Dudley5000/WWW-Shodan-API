use strict;
use warnings;
use Test::More tests => 21;
use lib 't';
use MockUA;

use WWW::Shodan::API;

my $KEY    = 'TESTKEY123';
my $shodan = WWW::Shodan::API->new($KEY);
my $mock   = MockUA->new();
$shodan->{UA} = $mock;

# --- notifiers ---
$mock->set_response(200, '{"matches":[{"id":"N1","provider":"email"}],"total":1}');
my $result = $shodan->notifiers();
my $req = $mock->last_request();
is($req->method, 'GET', 'notifiers uses GET');
like($req->uri, qr{/notifier(?:[?]|$)}, 'notifiers hits /notifier');
like($req->uri, qr{key=TESTKEY123}, 'notifiers sends API key');

# --- notifier_providers ---
$mock->set_response(200, '{"email":{"name":"Email"}}');
$result = $shodan->notifier_providers();
$req = $mock->last_request();
is($req->method, 'GET', 'notifier_providers uses GET');
like($req->uri, qr{/notifier/provider}, 'notifier_providers hits correct path');

# --- notifier_info ---
$mock->set_response(200, '{"id":"N1","provider":"email","description":"My email"}');
$result = $shodan->notifier_info('N1');
$req = $mock->last_request();
is($req->method, 'GET', 'notifier_info uses GET');
like($req->uri, qr{/notifier/N1(?:[?]|$)}, 'notifier_info puts ID in path');
is($result->{provider}, 'email', 'notifier_info returns decoded data');

# --- create_notifier (POST form-encoded) ---
$mock->set_response(200, '{"id":"N2"}');
$result = $shodan->create_notifier({
    provider    => 'email',
    description => 'My alerts',
    to          => 'me@example.com',
});
$req = $mock->last_request();
is($req->method, 'POST', 'create_notifier uses POST');
like($req->uri, qr{/notifier(?:[?]|$)}, 'create_notifier hits /notifier');
is($req->header('Content-Type'), 'application/x-www-form-urlencoded', 'create_notifier sends form body');
like($req->content, qr{provider=email}, 'create_notifier body has provider');
like($req->content, qr{description=}, 'create_notifier body has description');
like($req->content, qr{to=me%40example\.com}, 'create_notifier body has encoded to address');
is($result->{id}, 'N2', 'create_notifier returns id');

# --- edit_notifier (PUT form-encoded) ---
$mock->set_response(200, '{"success":true}');
$result = $shodan->edit_notifier({ id => 'N1', to => 'new@example.com' });
$req = $mock->last_request();
is($req->method, 'PUT', 'edit_notifier uses PUT');
like($req->uri, qr{/notifier/N1(?:[?]|$)}, 'edit_notifier puts ID in path');
is($req->header('Content-Type'), 'application/x-www-form-urlencoded', 'edit_notifier sends form body');
like($req->content, qr{to=new%40example\.com}, 'edit_notifier body has encoded to address');

# --- delete_notifier ---
$mock->set_response(200, '{"success":true}');
$result = $shodan->delete_notifier('N1');
$req = $mock->last_request();
is($req->method, 'DELETE', 'delete_notifier uses DELETE');
like($req->uri, qr{/notifier/N1(?:[?]|$)}, 'delete_notifier puts ID in path');
