package MockUA;
use strict;
use warnings;
use HTTP::Response;

sub new {
    my $class = shift;
    return bless { _response => undef, _last_request => undef }, $class;
}

sub set_response {
    my ($self, $status, $content) = @_;
    my $resp = HTTP::Response->new($status);
    $resp->content($content);
    $self->{_response} = $resp;
}

sub last_request { $_[0]->{_last_request} }

sub request {
    my ($self, $req) = @_;
    $self->{_last_request} = $req;
    return $self->{_response};
}

1;
