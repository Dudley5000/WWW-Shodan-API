package WWW::Shodan::API;

use 5.006;
use strict;
use warnings FATAL => 'all';

our $VERSION = '0.008';

use Carp;
use JSON;
use LWP::UserAgent;
use URI::Escape;

our $ua   = LWP::UserAgent->new;
our $json = JSON->new->allow_nonref;

use constant BASE_URL          => 'https://api.shodan.io';
use constant MY_IP_ENDPOINT    => '/tools/myip?key=';
use constant API_INFO_ENDPOINT => '/api-info?key=';
use constant SERVICES_ENDPOINT => '/shodan/services?key=';

use constant DNS_RESOLVE_ENDPOINT => '/dns/resolve?hostnames=HOSTNAMES&key=';
use constant DNS_REVERSE_ENDPOINT => '/dns/reverse?ips=IPS&key=';

use constant HOST_IP_ENDPOINT => '/shodan/host/IP?key=';
use constant SEARCH_ENDPOINT  => '/shodan/host/search?key=KEY&query=QUERY&facets=FACETS';
use constant COUNT_ENDPOINT   => '/shodan/host/count?key=KEY&query=QUERY&facets=FACETS';
use constant TOKENS_ENDPOINT  => '/shodan/host/search/tokens?key=KEY&query=QUERY';

sub new {
    my ( $class, $apikey ) = @_;
    my $self = { APIKEY => $apikey };
    bless $self, $class;
    return $self;
}

sub api_info {
    my $self     = shift;
    my $response = $ua->get( BASE_URL . API_INFO_ENDPOINT . $self->_get_apikey );
    if ( $response->is_success ) {
        my $result = $json->decode( $response->decoded_content );
        for my $value ( values %$result ) {
            next unless JSON::is_bool($value);
            $value = ( $value ? 'true' : 'false' );
        }
        return $result;
    }
    else {
        croak $response->status_line;
    }
}

sub resolve_dns {
    my ( $self, $hostnames ) = @_;
    my $end_point = DNS_RESOLVE_ENDPOINT;
    $hostnames = join( ",", @$hostnames );
    $end_point =~ s/HOSTNAMES/$hostnames/;
    my $response = $ua->get( BASE_URL . $end_point . $self->_get_apikey );
    if ( $response->is_success ) {
        return $json->decode( $response->decoded_content );
    }
    else {
        croak $response->status_line;
    }
}

sub reverse_dns {
    my ( $self, $ips ) = @_;
    my $end_point = DNS_REVERSE_ENDPOINT;
    $ips = join( ",", @$ips );
    $end_point =~ s/IPS/$ips/;
    my $response = $ua->get( BASE_URL . $end_point . $self->_get_apikey );
    if ( $response->is_success ) {
        return $json->decode( $response->decoded_content );
    }
    else {
        croak $response->status_line;
    }
}

sub host_ip {
    my ( $self, $args ) = @_;
    my $end_point = HOST_IP_ENDPOINT;
    my $ip        = $args->{IP};
    $end_point =~ s/IP/$ip/;
    $end_point .= $self->_get_apikey;
    $end_point .= '&history=true' if $args->{HISTORY};
    $end_point .= '&minify=true' if $args->{MINIFY};

    my $response = $ua->get( BASE_URL . $end_point );
    if ( $response->is_success ) {
        return $json->decode( $response->decoded_content );
    }
    else {
        croak $response->status_line;
    }
}

sub search {
    my ( $self, $query, $facet, $args ) = @_;
    my $end_point = SEARCH_ENDPOINT;
    my $apikey    = $self->_get_apikey;
    $end_point =~ s/KEY/$apikey/;
    my $str = '';

    if ( scalar keys %$query ) {
        for my $q ( keys %$query ) {
            $query->{$q} =~ s/ /+/g;
            $str .= $q . ':' . uri_escape( $query->{$q} ) . '+';
        }
    }
    $str       =~ s/\+$//;
    $end_point =~ s/QUERY/$str/;
    $end_point =~ s/&query=// unless scalar keys %$query;
    $str = '';

    # $facet is an array ref potentially containing hash refs
    # ex. [ 'org', 'port', { os => 50 } ]

    if ( scalar @$facet ) {
      FACET:
        for my $f (@$facet) {
            if ( ref $f eq 'HASH' ) {
                my ( $k, $v ) = each %$f;
                $str .= $k . ':' . uri_escape( $v . ',' );
                next FACET;
            }
            $str .= uri_escape( $f . ',' );
        }
    }

    my $plus      = uri_escape('+');
    my $comma     = uri_escape(',');
    my $ampersand = uri_escape('&');

    $str =~ s/$plus$//;
    $str =~ s/$comma$//;
    $str =~ s/$ampersand$//;

    $end_point =~ s/FACETS/$str/;
    $end_point =~ s/&facets=// unless scalar @$facet;

    if ( defined $args->{PAGE} ) {
        my $pgnum = $args->{PAGE};
        $end_point .= '&page=' . $pgnum;
    }

    $end_point .= '&minify=false' if defined $args->{NO_MINIFY};

    my $response = $ua->get( BASE_URL . $end_point );
    if ( $response->is_success ) {
        return $json->decode( $response->decoded_content );
    }
    else {
        croak $response->status_line;
    }
} ## end sub search

sub tokens {
    my ( $self, $query ) = @_;
    my $end_point = TOKENS_ENDPOINT;
    my $apikey    = $self->_get_apikey;
    $end_point =~ s/KEY/$apikey/;
    my $str = '';

    if ( scalar keys %$query ) {
        for my $q ( keys %$query ) {
            $query->{$q} =~ s/ /+/g;
            $str .= $q . ':' . uri_escape( $query->{$q} ) . '+';
        }
    }
    $str       =~ s/\+$//;
    $end_point =~ s/QUERY/$str/;
    $end_point =~ s/&query=// unless scalar keys %$query;

    my $response = $ua->get( BASE_URL . $end_point );
    if ( $response->is_success ) {
        return $json->decode( $response->decoded_content );
    }
    else {
        croak $response->status_line;
    }
}

sub count {
    my ( $self, $query, $facet ) = @_;
    my $end_point = COUNT_ENDPOINT;
    my $apikey    = $self->_get_apikey;
    $end_point =~ s/KEY/$apikey/;
    my $str = '';

    if ( scalar keys %$query ) {
        for my $q ( keys %$query ) {
            $query->{$q} =~ s/ /+/g;
            $str .= $q . ':' . uri_escape( $query->{$q} ) . '+';
        }
    }
    $str       =~ s/\+$//;
    $end_point =~ s/QUERY/$str/;
    $end_point =~ s/&query=// unless scalar keys %$query;
    $str = '';

    # $facet is an array ref potentially containing hash refs
    # ex. [ 'org', 'port', { os => 50 } ]

    if ( scalar @$facet ) {
      FACET:
        for my $f (@$facet) {
            if ( ref $f eq 'HASH' ) {
                my ( $k, $v ) = each %$f;
                $str .= $k . ':' . uri_escape( $v . ',' );
                next FACET;
            }
            $str .= uri_escape( $f . ',' );
        }
    }

    my $plus      = uri_escape('+');
    my $comma     = uri_escape(',');
    my $ampersand = uri_escape('&');

    $str =~ s/$plus$//;
    $str =~ s/$comma$//;
    $str =~ s/$ampersand$//;

    $end_point =~ s/FACETS/$str/;
    $end_point =~ s/&facets=// unless scalar @$facet;

    my $response = $ua->get( BASE_URL . $end_point );
    if ( $response->is_success ) {
        return $json->decode( $response->decoded_content );
    }
    else {
        croak $response->status_line;
    }
} ## end sub count

sub my_ip {
    my $self     = shift;
    my $response = $ua->get( BASE_URL . MY_IP_ENDPOINT . $self->_get_apikey );
    if ( $response->is_success ) {
        return $json->decode( $response->decoded_content );
    }
    else {
        croak $response->status_line;
    }
}

sub services {
    my $self     = shift;
    my $response = $ua->get( BASE_URL . SERVICES_ENDPOINT . $self->_get_apikey );
    if ( $response->is_success ) {
        return $json->decode( $response->decoded_content );
    }
    else {
        croak $response->status_line;
    }
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

Version 0.008

=cut


=head1 OVERVIEW

This module is to provide your Perl applications with easy access to the L<Shodan API|https://developer.shodan.io/api>.

=head1 SYNOPSIS

	use WWW::Shodan::API;
	use Data::Dumper;

	use constant APIKEY => '7hI5i5n07@re@L@Pik3Yd0n7b3@dumMY';

	my $shodan = WWW::Shodan::API->new( APIKEY );

	print Dumper $shodan->api_info;
	print Dumper $shodan->services;

=head1 GETTING STARTED

=over 2

=item * In order to use the Shodan API you need to have an API key, which can be obtained for free by creating a L<Shodan account|https://account.shodan.io/register>.

=item * Become familiar with the L<Shodan REST API Documentation|https://developer.shodan.io/api>.

=back

=head1 METHODS

=head1 SHODAN METHODS

=head3 $shodan->host_ip

Host Information - Returns all services that have been found on the given host IP.

	$shodan->host_ip({ IP => '12.34.567.890' [,HISTORY => 1 [,MINIFY => 1]] })

B<Parameters>:

This method accepts a hash reference as an argument, with three possible key/value pairs:

=over 2

=item C<IP> (required): Host IP address

=item C<HISTORY> (optional): True if all historical banners should be returned (default: False)

=item C<MINIFY> (optional): True to only return the list of ports and the general host information, no banners. (default: False)

=back

=head3 $shodan->search

Search Shodan - Search Shodan using the same query syntax as the website and use facets to get summary information for different properties.

    my $query = {
        product => 'Apache',
        port    => 80,
        link    => 'AX.25 radio modem',
        os      => 'windows 7 or 8',
        before  => '28/05/2014',
        after   => '17/03/2011',
        country => 'US',
    };

    my $facets = [ { 'isp' => 3 }, { 'os' => 2 }, 'version' ];

    $shodan->search( $query, $facets, [{ PAGE => 5 [,NO_MINIFY => 1] }] )

B<Note:> This method may use API query credits depending on usage. If any of the following criteria are met, your account will be deducated 1 query credit:

=over 4

=item The search query contains a filter.

=item Accessing results past the 1st page using the "page". For every 100 results past the 1st page 1 query credit is deducted.

=back

B<Parameters>:

The first argument is the C<query> (required). It is a hash reference consisting of key/values pairs. For the full list of acceptable key/value pairs, consult the L<Shodan REST API Documentation|https://developer.shodan.io/api>.

The next argument is C<facets>, and will be a list of properties on which to summarize. It is an array reference containing strings and hash references. In the above example, the query response will include summary data for F<isp>, F<os>, and F<version>, however only the first 3 F<isp> results will be returned and only the first 2 F<os> results will be returned. The F<version> will also be summarized, but will not be limited to a particular count. All distinct F<version>s will be returned in the resultset. For the full list of acceptable facets, consult the L<Shodan REST API Documentation|https://developer.shodan.io/api>.

The third argument is an optional hash reference which may contain one or both of the following keys:

C<PAGE> - The page number to page through results 100 at a time (default: 1). In the above example, the query response will be limited to results 500-600 of the total resultset.

C<NO_MINIFY> - If supplied, some of the larger fields in the resultset will not be truncated. The default is to truncate those fields.

=head3 $shodan->count

Search Shodan without Results

    $shodan->count( $query, $facets )

B<Parameters>:

This method behaves exactly as C<$shodan-E<gt>search> with the only difference being that this method does not return any host results, it returns the total number of results that matched the query and any facet information that was requested. As a result, this method does not consume query credits.

The arguments to this method are identical to C<$shodan-E<gt>search>, except this one does not take an optional hash for C<PAGE> and C<NO_MINIFY> since this method only returns a count of results.

=head3 $shodan->tokens

Break the search query into tokens - This method lets you determine which filters are being used by the query string and what parameters were provided to the filters.

    $shodan->tokens( $query )

B<Parameters>:

The only argument to this method is the C<query> (required). For details on how to form the C<query>, see the example for C<$shodan-E<gt>search>.

=head3 $shodan->services

List all services that Shodan crawls - This method returns an object containing all the services that the Shodan crawlers look at. It can also be used as a quick and practical way to resolve a port number to the name of a service.

    $shodan->services

B<Parameters>:

None

=head1 DNS METHODS

=head3 $shodan->resolve_dns

DNS Lookup - Look up the IP address for the provided list of hostnames

    $shodan->resolve_dns([ qw/google.com bing.com amazon.com/ ])

B<Parameters>:

This method takes one argument, an array reference of domains to be resolved into ip addresses

=head3 $shodan->reverse_dns

Reverse DNS Lookup - Look up the hostnames that have been defined for the given list of IP addresses

    $shodan->reverse_dns([ qw/74.125.227.230 204.79.197.200/ ])

B<Parameters>:

This method takes one argument, an array reference of ips to be returned as hostnames

=head1 UTILITY METHODS

=head3 $shodan->my_ip

My IP Address - Get your current IP address as seen from the Internet

    $shodan->my_ip

B<Parameters>:

None

=head1 API STATUS METHODS

=head3 $shodan->api_info

API Plan Information - Returns information about the API plan belonging to the given API key

    $shodan->api_info

B<Parameters>:

None

=head1 AUTHOR

Dudley Adams, C<< <dudleyadams at gmail.com> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-www-shodan-api at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=WWW-Shodan-API>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.

=head1 SUPPORT

You can find documentation for this module with the perldoc command.

	perldoc WWW::Shodan::API

You can also look for information at:

=over 4

=item * RT: CPAN's request tracker (report bugs here)

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=WWW-Shodan-API>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/WWW-Shodan-API>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/WWW-Shodan-API>

=item * Search CPAN

L<http://search.cpan.org/dist/WWW-Shodan-API/>

=back

=head1 LICENSE AND COPYRIGHT

Copyright 2014 Dudley Adams.

This program is free software; you can redistribute it and/or modify it
under the terms of the the Artistic License (2.0). You may obtain a
copy of the full license at:

L<http://www.perlfoundation.org/artistic_license_2_0>

Any use, modification, and distribution of the Standard or Modified
Versions is governed by this Artistic License. By using, modifying or
distributing the Package, you accept this license. Do not use, modify,
or distribute the Package, if you do not accept this license.

If your Modified Version has been derived from a Modified Version made
by someone other than you, you are nevertheless required to ensure that
your Modified Version complies with the requirements of this license.

This license does not grant you the right to use any trademark, service
mark, tradename, or logo of the Copyright Holder.

This license includes the non-exclusive, worldwide, free-of-charge
patent license to make, have made, use, offer to sell, sell, import and
otherwise transfer the Package with respect to any patent claims
licensable by the Copyright Holder that are necessarily infringed by the
Package. If you institute patent litigation (including a cross-claim or
counterclaim) against any party alleging that the Package constitutes
direct or contributory patent infringement, then this Artistic License
to you shall terminate on the date that such litigation is filed.

Disclaimer of Warranty: THE PACKAGE IS PROVIDED BY THE COPYRIGHT HOLDER
AND CONTRIBUTORS "AS IS' AND WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES.
THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
PURPOSE, OR NON-INFRINGEMENT ARE DISCLAIMED TO THE EXTENT PERMITTED BY
YOUR LOCAL LAW. UNLESS REQUIRED BY LAW, NO COPYRIGHT HOLDER OR
CONTRIBUTOR WILL BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, OR
CONSEQUENTIAL DAMAGES ARISING IN ANY WAY OUT OF THE USE OF THE PACKAGE,
EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

=cut

