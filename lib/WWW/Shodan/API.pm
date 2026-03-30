package WWW::Shodan::API;

use 5.006;
use strict;
use warnings FATAL => 'all';

our $VERSION = '0.021';

use Carp;
use HTTP::Request;
use JSON;
use LWP::UserAgent;
use URI;
use URI::Escape;

use constant BASE_URL => 'https://api.shodan.io';

sub new {
    my ( $class, $apikey ) = @_;
    my $ua   = LWP::UserAgent->new;
    my $json = JSON->new->allow_nonref;

    my $self = {
        APIKEY => $apikey,
        UA     => $ua,
        JSON   => $json,
    };
    bless $self, $class;
    return $self;
}

sub _ua {
    my $self = shift;
    return $self->{UA};
}

sub _json {
    my $self = shift;
    return $self->{JSON};
}

sub _request {
    my ( $self, $method, $path, %opts ) = @_;

    my $uri   = URI->new( BASE_URL . $path );
    my %query = ( key => $self->_get_apikey, %{ $opts{query} // {} } );
    $uri->query_form( %query );

    my $req = HTTP::Request->new( $method => $uri->as_string );

    if ( $opts{json} ) {
        $req->header( 'Content-Type' => 'application/json' );
        $req->content( $self->_json->encode( $opts{json} ) );
    }
    elsif ( $opts{form} ) {
        my $tmp = URI->new( 'http://x/' );
        $tmp->query_form( %{ $opts{form} } );
        $req->header( 'Content-Type' => 'application/x-www-form-urlencoded' );
        $req->content( $tmp->query // '' );
    }

    my $response = $self->_ua->request( $req );
    my $data;
    eval { $data = $self->_json->decode( $response->decoded_content ) };

    if ( $response->is_success && defined $data ) {
        return $data;
    }
    else {
        croak sprintf "%s - %s",
          $response->status_line,
          ( $data && $data->{error} ) ? $data->{error} : 'API provided no error message';
    }
}

sub api_info {
    my $self   = shift;
    my $result = $self->_request( 'GET', '/api-info' );
    for my $value ( values %$result ) {
        next unless JSON::is_bool( $value );
        $value = ( $value ? 'true' : 'false' );
    }
    return $result;
}

sub resolve_dns {
    my ( $self, $hostnames ) = @_;
    my $hosts = join( ",", @$hostnames );
    return $self->_request( 'GET', '/dns/resolve', query => { hostnames => $hosts } );
}

sub reverse_dns {
    my ( $self, $ips ) = @_;
    return $self->_request( 'GET', '/dns/reverse',
        query => { ips => join( ',', @$ips ) } );
}

sub host_ip {
    my ( $self, $args ) = @_;
    my %query;
    $query{history} = 'true' if $args->{HISTORY};
    $query{minify}  = 'true' if $args->{MINIFY};
    return $self->_request( 'GET', "/shodan/host/$args->{IP}", query => \%query );
}

sub _build_query_str {
    my ( $query ) = @_;
    return '' unless ref $query eq 'HASH' && scalar keys %$query;
    return join( ' ', map { "$_:$query->{$_}" } keys %$query );
}

sub _build_facets_str {
    my ( $facets ) = @_;
    return '' unless ref $facets eq 'ARRAY' && scalar @$facets;
    my @parts;
    for my $f ( @$facets ) {
        if ( ref $f eq 'HASH' ) {
            my ( $k ) = keys %$f;
            my $v = $f->{$k};
            push @parts, "$k:$v";
        }
        else {
            push @parts, $f;
        }
    }
    return join( ',', @parts );
}

sub search {
    my ( $self, $query, $facet, $args ) = @_;
    $facet //= [];
    $args  //= {};
    my %params;
    my $qstr = _build_query_str( $query );
    $params{query} = $qstr if $qstr;
    my $fstr = _build_facets_str( $facet );
    $params{facets} = $fstr         if $fstr;
    $params{page}   = $args->{PAGE} if defined $args->{PAGE};
    $params{minify} = 'false'       if defined $args->{NO_MINIFY};
    return $self->_request( 'GET', '/shodan/host/search', query => \%params );
}

sub tokens {
    my ( $self, $query ) = @_;
    my %params;
    my $qstr = _build_query_str( $query );
    $params{query} = $qstr if $qstr;
    return $self->_request( 'GET', '/shodan/host/search/tokens', query => \%params );
}

sub count {
    my ( $self, $query, $facet ) = @_;
    $facet //= [];
    my %params;
    my $qstr = _build_query_str( $query );
    $params{query} = $qstr if $qstr;
    my $fstr = _build_facets_str( $facet );
    $params{facets} = $fstr if $fstr;
    return $self->_request( 'GET', '/shodan/host/count', query => \%params );
}

sub my_ip {
    my $self = shift;
    return $self->_request( 'GET', '/tools/myip' );
}

sub services {
    my $self = shift;
    return $self->_request( 'GET', '/shodan/services' );
}

# Search additions

sub search_facets {
    my $self = shift;
    return $self->_request( 'GET', '/shodan/host/search/facets' );
}

sub search_filters {
    my $self = shift;
    return $self->_request( 'GET', '/shodan/host/search/filters' );
}

# On-Demand Scanning

sub ports {
    my $self = shift;
    return $self->_request( 'GET', '/shodan/ports' );
}

sub protocols {
    my $self = shift;
    return $self->_request( 'GET', '/shodan/protocols' );
}

sub scan {
    my ( $self, $ips ) = @_;
    return $self->_request( 'POST', '/shodan/scan',
        form => { ips => join( ',', @$ips ) } );
}

sub scan_internet {
    my ( $self, $args ) = @_;
    return $self->_request( 'POST', '/shodan/scan/internet',
        form => { port => $args->{port}, protocol => $args->{protocol} } );
}

sub scans {
    my $self = shift;
    return $self->_request( 'GET', '/shodan/scans' );
}

sub scan_status {
    my ( $self, $id ) = @_;
    return $self->_request( 'GET', "/shodan/scan/$id" );
}

# Network Alerts

sub create_alert {
    my ( $self, $args ) = @_;
    my %body = (
        name    => $args->{name},
        filters => { ip => $args->{ips} },
    );
    $body{expires} = $args->{expires} if defined $args->{expires};
    return $self->_request( 'POST', '/shodan/alert', json => \%body );
}

sub alerts_info {
    my $self = shift;
    return $self->_request( 'GET', '/shodan/alert/info' );
}

sub alert_info {
    my ( $self, $id ) = @_;
    return $self->_request( 'GET', "/shodan/alert/$id/info" );
}

sub edit_alert {
    my ( $self, $args ) = @_;
    return $self->_request( 'POST', "/shodan/alert/$args->{id}",
        json => { filters => { ip => $args->{ips} } } );
}

sub delete_alert {
    my ( $self, $id ) = @_;
    return $self->_request( 'DELETE', "/shodan/alert/$id" );
}

sub alert_triggers {
    my $self = shift;
    return $self->_request( 'GET', '/shodan/alert/triggers' );
}

sub enable_trigger {
    my ( $self, $args ) = @_;
    return $self->_request( 'PUT', "/shodan/alert/$args->{id}/trigger/$args->{trigger}" );
}

sub disable_trigger {
    my ( $self, $args ) = @_;
    return $self->_request( 'DELETE', "/shodan/alert/$args->{id}/trigger/$args->{trigger}" );
}

sub add_whitelist {
    my ( $self, $args ) = @_;
    my $svc = uri_escape( $args->{service} );
    return $self->_request( 'PUT',
        "/shodan/alert/$args->{id}/trigger/$args->{trigger}/ignore/$svc" );
}

sub remove_whitelist {
    my ( $self, $args ) = @_;
    my $svc = uri_escape( $args->{service} );
    return $self->_request( 'DELETE',
        "/shodan/alert/$args->{id}/trigger/$args->{trigger}/ignore/$svc" );
}

sub add_notifier {
    my ( $self, $args ) = @_;
    return $self->_request( 'PUT', "/shodan/alert/$args->{id}/notifier/$args->{notifier_id}" );
}

sub remove_notifier {
    my ( $self, $args ) = @_;
    return $self->_request( 'DELETE', "/shodan/alert/$args->{id}/notifier/$args->{notifier_id}" );
}

# Notifiers

sub notifiers {
    my $self = shift;
    return $self->_request( 'GET', '/notifier' );
}

sub notifier_providers {
    my $self = shift;
    return $self->_request( 'GET', '/notifier/provider' );
}

sub notifier_info {
    my ( $self, $id ) = @_;
    return $self->_request( 'GET', "/notifier/$id" );
}

sub create_notifier {
    my ( $self, $args ) = @_;
    return $self->_request( 'POST', '/notifier',
        form => {
            provider    => $args->{provider},
            description => $args->{description},
            to          => $args->{to},
        } );
}

sub edit_notifier {
    my ( $self, $args ) = @_;
    my %body;
    $body{provider}    = $args->{provider}    if defined $args->{provider};
    $body{description} = $args->{description} if defined $args->{description};
    $body{to}          = $args->{to}          if defined $args->{to};
    return $self->_request( 'PUT', "/notifier/$args->{id}", form => \%body );
}

sub delete_notifier {
    my ( $self, $id ) = @_;
    return $self->_request( 'DELETE', "/notifier/$id" );
}

# Directory Methods

sub queries {
    my ( $self, $args ) = @_;
    $args //= {};
    return $self->_request( 'GET', '/shodan/query', query => $args );
}

sub search_queries {
    my ( $self, $args ) = @_;
    $args //= {};
    return $self->_request( 'GET', '/shodan/query/search', query => $args );
}

sub query_tags {
    my ( $self, $args ) = @_;
    $args //= {};
    return $self->_request( 'GET', '/shodan/query/tags', query => $args );
}

# Account Methods

sub profile {
    my $self = shift;
    return $self->_request( 'GET', '/account/profile' );
}

# DNS additions

sub domain_info {
    my ( $self, $args ) = @_;
    $args = { domain => $args } unless ref $args;
    my $domain = delete $args->{domain};
    return $self->_request( 'GET', "/dns/domain/$domain", query => $args );
}

# Utility additions

sub http_headers {
    my $self = shift;
    return $self->_request( 'GET', '/tools/httpheaders' );
}

sub _get_apikey {
    my $self = shift;
    return $self->{APIKEY};
}

1;    # End of WWW::Shodan::API

__DATA__

=head1 NAME

WWW::Shodan::API - Interface for the Shodan Computer Search Engine API

=head1 VERSION

Version 0.021

=cut

=head1 OVERVIEW

This module provides Perl applications with easy access to the L<Shodan API|https://developer.shodan.io/api>.

=head1 SYNOPSIS

    use WWW::Shodan::API;
    use Data::Dumper;

    use constant APIKEY => '7hI5i5n07@re@L@Pik3Yd0n7b3@dumMY';

    my $shodan = WWW::Shodan::API->new( APIKEY );

    print Dumper $shodan->api_info;
    print Dumper $shodan->profile;
    print Dumper $shodan->host_ip({ IP => '8.8.8.8' });

    # Search
    my $results = $shodan->search({ port => 80, product => 'Apache' }, ['org', 'country'], {});
    print Dumper $results;

    # Alerts
    my $alert = $shodan->create_alert({ name => 'My Network', ips => ['1.2.3.0/24'] });
    print "Alert ID: $alert->{id}\n";

=head1 GETTING STARTED

=over 2

=item * In order to use the Shodan API you need to have an API key, which can be obtained for free by creating a L<Shodan account|https://account.shodan.io/register>.

=item * Become familiar with the L<Shodan REST API Documentation|https://developer.shodan.io/api>.

=back

=head1 METHODS

=head3 new

Constructor - Creates a new WWW::Shodan::API object.

    my $shodan = WWW::Shodan::API->new($apikey);

Takes a Shodan API key as its only argument.

=head1 SHODAN SEARCH METHODS

=head3 $shodan->host_ip

Host Information - Returns all services that have been found on the given host IP.

    $shodan->host_ip({ IP => '12.34.56.78' [, HISTORY => 1 [, MINIFY => 1]] })

B<Parameters>: Hash reference with keys:

=over 2

=item C<IP> (required): Host IP address

=item C<HISTORY> (optional): True to return all historical banners (default: false)

=item C<MINIFY> (optional): True to return only ports and general host info, no banners (default: false)

=back

=head3 $shodan->search

Search Shodan using the same query syntax as the website. May consume query credits.

    my $query  = { product => 'Apache', port => 80, country => 'US' };
    my $facets = [ { isp => 3 }, { os => 2 }, 'version' ];
    $shodan->search( $query, $facets, { PAGE => 2 } )

B<Parameters>:

=over 2

=item C<$query> (required): Hash reference of search filter key/value pairs.

=item C<$facets> (optional): Array reference of facets. Each element is either a string (e.g. C<'org'>) or a hash ref specifying a count limit (e.g. C<{ os =E<gt> 5 }>).

=item C<$args> (optional): Hash reference with optional keys C<PAGE> (page number, default 1) and C<NO_MINIFY> (if set, larger fields are not truncated).

=back

=head3 $shodan->count

Search Shodan without returning results - returns only the total count and facet data. Does not consume query credits.

    $shodan->count( $query, $facets )

Arguments are identical to C<$shodan-E<gt>search> except C<PAGE> and C<NO_MINIFY> are not accepted.

=head3 $shodan->tokens

Break a search query string into its component tokens and filters.

    $shodan->tokens({ product => 'Apache', port => 80 })

=head3 $shodan->search_facets

List all search facets available in Shodan.

    $shodan->search_facets

=head3 $shodan->search_filters

List all filters that can be used when searching Shodan.

    $shodan->search_filters

=head1 ON-DEMAND SCANNING METHODS

=head3 $shodan->ports

List all ports that Shodan is currently crawling on the Internet.

    $shodan->ports

=head3 $shodan->protocols

List all protocols that can be used for on-demand Internet scans.

    $shodan->protocols

=head3 $shodan->scan

Request Shodan to crawl one or more IPs or netblocks.

    $shodan->scan([ '1.2.3.4', '5.6.7.0/24' ])

B<Parameters>: Array reference of IP addresses and/or CIDR netblocks.

=head3 $shodan->scan_internet

Crawl the entire Internet for a specific port and protocol. Requires an academic or enterprise API plan.

    $shodan->scan_internet({ port => 80, protocol => 'http' })

=head3 $shodan->scans

Get a list of all scans you have submitted.

    $shodan->scans

=head3 $shodan->scan_status

Get the status of a previously submitted scan request.

    $shodan->scan_status('SCAN_ID')

=head1 NETWORK ALERT METHODS

=head3 $shodan->create_alert

Create a network alert to monitor a set of IPs or netblocks.

    $shodan->create_alert({ name => 'My Network', ips => ['1.2.3.0/24'], expires => 0 })

B<Parameters>: Hash reference with keys:

=over 2

=item C<name> (required): Name of the alert.

=item C<ips> (required): Array reference of IPs or CIDR netblocks to monitor.

=item C<expires> (optional): Unix timestamp when the alert expires (0 = never).

=back

=head3 $shodan->alerts_info

Get a list of all network alerts you have created.

    $shodan->alerts_info

=head3 $shodan->alert_info

Get details for a specific network alert.

    $shodan->alert_info('ALERT_ID')

=head3 $shodan->edit_alert

Edit the networks monitored by an existing alert.

    $shodan->edit_alert({ id => 'ALERT_ID', ips => ['1.2.3.0/24', '5.6.7.0/24'] })

=head3 $shodan->delete_alert

Delete a network alert.

    $shodan->delete_alert('ALERT_ID')

=head3 $shodan->alert_triggers

Get a list of available triggers that can be attached to alerts.

    $shodan->alert_triggers

=head3 $shodan->enable_trigger

Enable a trigger on an alert.

    $shodan->enable_trigger({ id => 'ALERT_ID', trigger => 'malware' })

=head3 $shodan->disable_trigger

Disable a trigger on an alert.

    $shodan->disable_trigger({ id => 'ALERT_ID', trigger => 'malware' })

=head3 $shodan->add_whitelist

Add an IP/port service to the whitelist for a trigger (so it doesn't generate notifications).

    $shodan->add_whitelist({ id => 'ALERT_ID', trigger => 'malware', service => '1.2.3.4:80' })

The C<service> value must be in C<ip:port> format.

=head3 $shodan->remove_whitelist

Remove a service from a trigger's whitelist.

    $shodan->remove_whitelist({ id => 'ALERT_ID', trigger => 'malware', service => '1.2.3.4:80' })

=head3 $shodan->add_notifier

Attach a notifier to an alert so it receives trigger notifications.

    $shodan->add_notifier({ id => 'ALERT_ID', notifier_id => 'NOTIFIER_ID' })

=head3 $shodan->remove_notifier

Remove a notifier from an alert.

    $shodan->remove_notifier({ id => 'ALERT_ID', notifier_id => 'NOTIFIER_ID' })

=head1 NOTIFIER METHODS

=head3 $shodan->notifiers

List all notification services you have created.

    $shodan->notifiers

=head3 $shodan->notifier_providers

List all available notification providers (e.g. email, Slack).

    $shodan->notifier_providers

=head3 $shodan->notifier_info

Get information about a specific notifier.

    $shodan->notifier_info('NOTIFIER_ID')

=head3 $shodan->create_notifier

Create a new notification service.

    $shodan->create_notifier({
        provider    => 'email',
        description => 'My alert emails',
        to          => 'me@example.com',
    })

=head3 $shodan->edit_notifier

Edit the destination address of an existing notifier.

    $shodan->edit_notifier({ id => 'NOTIFIER_ID', to => 'new@example.com' })

=head3 $shodan->delete_notifier

Delete a notification service.

    $shodan->delete_notifier('NOTIFIER_ID')

=head1 DIRECTORY METHODS

=head3 $shodan->queries

List saved search queries from the Shodan community directory.

    $shodan->queries
    $shodan->queries({ page => 1, sort => 'votes', order => 'desc' })

B<Optional parameters>: C<page> (default 1), C<sort> (C<'votes'> or C<'timestamp'>), C<order> (C<'asc'> or C<'desc'>).

=head3 $shodan->search_queries

Search the directory of saved queries.

    $shodan->search_queries({ query => 'apache' })
    $shodan->search_queries({ query => 'apache', page => 2 })

=head3 $shodan->query_tags

List the most popular tags in the saved query directory.

    $shodan->query_tags
    $shodan->query_tags({ size => 10 })

=head1 DNS METHODS

=head3 $shodan->resolve_dns

DNS Lookup - Look up the IP address for the provided list of hostnames.

    $shodan->resolve_dns([ qw/google.com bing.com/ ])

=head3 $shodan->reverse_dns

Reverse DNS Lookup - Look up the hostnames defined for the given list of IP addresses.

    $shodan->reverse_dns([ qw/74.125.227.230 204.79.197.200/ ])

=head3 $shodan->domain_info

Get all DNS entries and subdomains for a domain. Accepts either a plain domain string or a hash reference for optional parameters.

    $shodan->domain_info('google.com')
    $shodan->domain_info({ domain => 'google.com', history => 1, type => 'A' })

B<Optional parameters>: C<history> (include historical DNS data), C<type> (DNS record type filter, e.g. C<'A'>, C<'MX'>).

=head1 UTILITY METHODS

=head3 $shodan->my_ip

Get your current IP address as seen from the Internet.

    $shodan->my_ip

=head3 $shodan->http_headers

View the HTTP headers that your client sends when connecting to a web server.

    $shodan->http_headers

=head3 $shodan->services

List all services and their port numbers that Shodan recognises. Returns a hash of port => service-name mappings.

    $shodan->services

=head1 API STATUS METHODS

=head3 $shodan->api_info

Returns information about the API plan belonging to the given API key.

    $shodan->api_info

=head1 ACCOUNT METHODS

=head3 $shodan->profile

Returns information about the account associated with the API key.

    $shodan->profile

=head1 AUTHOR

Dudley Adams, C<< <dudleyadams at gmail.com> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-www-shodan-api at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=WWW-Shodan-API>.

=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc WWW::Shodan::API

=over 4

=item * RT: CPAN's request tracker

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=WWW-Shodan-API>

=item * Search CPAN

L<http://search.cpan.org/dist/WWW-Shodan-API/>

=back

=head1 SOURCE CODE

L<https://github.com/Dudley5000/WWW-Shodan-API>

    git clone https://github.com/Dudley5000/WWW-Shodan-API.git

=head1 LICENSE AND COPYRIGHT

Copyright 2014 Dudley Adams.

This program is free software; you can redistribute it and/or modify it
under the terms of the the Artistic License (2.0). You may obtain a
copy of the full license at:

L<http://www.perlfoundation.org/artistic_license_2_0>

=cut