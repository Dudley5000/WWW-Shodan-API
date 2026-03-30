use strict;
use warnings;
use Test::More tests => 32;
use lib 't';
use MockUA;
use JSON;

use WWW::Shodan::API;

my $KEY    = 'TESTKEY123';
my $shodan = WWW::Shodan::API->new($KEY);
my $mock   = MockUA->new();
$shodan->{UA} = $mock;
my $json = JSON->new->allow_nonref;

# --- create_alert (POST JSON) ---
$mock->set_response(200, '{"id":"ALERT1","name":"My Net","filters":{"ip":["1.2.3.0/24"]}}');
my $result = $shodan->create_alert({ name => 'My Net', ips => ['1.2.3.0/24'] });
my $req = $mock->last_request();
is($req->method, 'POST', 'create_alert uses POST');
like($req->uri, qr{/shodan/alert(?=[?])}, 'create_alert hits /shodan/alert');
is($req->header('Content-Type'), 'application/json', 'create_alert sends JSON body');
my $body = $json->decode($req->content);
is($body->{name}, 'My Net', 'create_alert body has name');
is_deeply($body->{filters}{ip}, ['1.2.3.0/24'], 'create_alert body has filters.ip');
is($result->{id}, 'ALERT1', 'create_alert returns decoded response');

# create_alert with expires
$mock->set_response(200, '{"id":"ALERT2"}');
$shodan->create_alert({ name => 'Temp', ips => ['1.2.3.4/32'], expires => 1234567890 });
$req = $mock->last_request();
$body = $json->decode($req->content);
is($body->{expires}, 1234567890, 'create_alert sends expires when provided');

# --- alerts_info ---
$mock->set_response(200, '[{"id":"ALERT1","name":"My Net"}]');
$result = $shodan->alerts_info();
$req = $mock->last_request();
is($req->method, 'GET', 'alerts_info uses GET');
like($req->uri, qr{/shodan/alert/info}, 'alerts_info hits correct path');

# --- alert_info ---
$mock->set_response(200, '{"id":"ALERT1","name":"My Net","filters":{"ip":["1.2.3.0/24"]}}');
$result = $shodan->alert_info('ALERT1');
$req = $mock->last_request();
is($req->method, 'GET', 'alert_info uses GET');
like($req->uri, qr{/shodan/alert/ALERT1/info}, 'alert_info puts ID in path');

# --- edit_alert (POST JSON) ---
$mock->set_response(200, '{"id":"ALERT1"}');
$result = $shodan->edit_alert({ id => 'ALERT1', ips => ['1.2.3.0/24', '5.6.7.0/24'] });
$req = $mock->last_request();
is($req->method, 'POST', 'edit_alert uses POST');
like($req->uri, qr{/shodan/alert/ALERT1(?=[?])}, 'edit_alert puts ID in path');
is($req->header('Content-Type'), 'application/json', 'edit_alert sends JSON body');
$body = $json->decode($req->content);
is(scalar @{$body->{filters}{ip}}, 2, 'edit_alert body has two IPs in filters');

# --- delete_alert ---
$mock->set_response(200, '{"success":true}');
$result = $shodan->delete_alert('ALERT1');
$req = $mock->last_request();
is($req->method, 'DELETE', 'delete_alert uses DELETE');
like($req->uri, qr{/shodan/alert/ALERT1(?=[?])}, 'delete_alert puts ID in path');

# --- alert_triggers ---
$mock->set_response(200, '[{"name":"malware","description":"Malware"}]');
$result = $shodan->alert_triggers();
$req = $mock->last_request();
is($req->method, 'GET', 'alert_triggers uses GET');
like($req->uri, qr{/shodan/alert/triggers}, 'alert_triggers hits correct path');

# --- enable_trigger (PUT, no body) ---
$mock->set_response(200, '{"success":true}');
$result = $shodan->enable_trigger({ id => 'ALERT1', trigger => 'malware' });
$req = $mock->last_request();
is($req->method, 'PUT', 'enable_trigger uses PUT');
like($req->uri, qr{/shodan/alert/ALERT1/trigger/malware(?=[?])}, 'enable_trigger puts id+trigger in path');
ok(!$req->content, 'enable_trigger sends no body');

# --- disable_trigger (DELETE) ---
$mock->set_response(200, '{"success":true}');
$result = $shodan->disable_trigger({ id => 'ALERT1', trigger => 'malware' });
$req = $mock->last_request();
is($req->method, 'DELETE', 'disable_trigger uses DELETE');
like($req->uri, qr{/shodan/alert/ALERT1/trigger/malware(?=[?])}, 'disable_trigger puts id+trigger in path');

# --- add_whitelist (PUT, no body) ---
$mock->set_response(200, '{"success":true}');
$result = $shodan->add_whitelist({ id => 'ALERT1', trigger => 'malware', service => '1.2.3.4:80' });
$req = $mock->last_request();
is($req->method, 'PUT', 'add_whitelist uses PUT');
like($req->uri, qr{/shodan/alert/ALERT1/trigger/malware/ignore/}, 'add_whitelist path structure');

# --- remove_whitelist (DELETE) ---
$mock->set_response(200, '{"success":true}');
$result = $shodan->remove_whitelist({ id => 'ALERT1', trigger => 'malware', service => '1.2.3.4:80' });
$req = $mock->last_request();
is($req->method, 'DELETE', 'remove_whitelist uses DELETE');
like($req->uri, qr{/shodan/alert/ALERT1/trigger/malware/ignore/}, 'remove_whitelist path structure');

# --- add_notifier (PUT, no body) ---
$mock->set_response(200, '{"success":true}');
$result = $shodan->add_notifier({ id => 'ALERT1', notifier_id => 'NOTIF1' });
$req = $mock->last_request();
is($req->method, 'PUT', 'add_notifier uses PUT');
like($req->uri, qr{/shodan/alert/ALERT1/notifier/NOTIF1(?=[?])}, 'add_notifier puts ids in path');

# --- remove_notifier (DELETE) ---
$mock->set_response(200, '{"success":true}');
$result = $shodan->remove_notifier({ id => 'ALERT1', notifier_id => 'NOTIF1' });
$req = $mock->last_request();
is($req->method, 'DELETE', 'remove_notifier uses DELETE');
like($req->uri, qr{/shodan/alert/ALERT1/notifier/NOTIF1(?=[?])}, 'remove_notifier puts ids in path');
