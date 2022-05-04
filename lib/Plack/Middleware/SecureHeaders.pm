package Plack::Middleware::SecureHeaders;
use strict;
use warnings;
use parent qw( Plack::Middleware );

our $VERSION = "0.01";

use Plack::Util::Accessor qw(
    content_security_policy
    strict_transport_security
    x_content_type_options
    x_download_options
    x_frame_options
    x_permitted_cross_domain_policies
    x_xss_protection
    referrer_policy
);

my %DEFAULT_HEADERS = (
    content_security_policy           => "default-src 'self' https:; font-src 'self' https: data:; img-src 'self' https: data:; object-src 'none'; script-src https:; style-src 'self' https: 'unsafe-inline'",
    strict_transport_security         => 'max-age=631138519',
    x_content_type_options            => 'nosniff',
    x_download_options                => 'noopen',
    x_frame_options                   => 'SAMEORIGIN',
    x_permitted_cross_domain_policies => 'none',
    x_xss_protection                  => '1; mode=block',
    referrer_policy                   => 'strict-origin-when-cross-origin',
);


sub prepare_app {
    my $self = shift;
    for my $key (keys %DEFAULT_HEADERS) {
        unless (defined $self->$key) {
            $self->$key($DEFAULT_HEADERS{$key})
        }
    }
}

sub call {
    my($self, $env) = @_;

    my $res = $self->app->($env);
    my $header = Plack::Util::headers($res->[1]);

    unless ($header->exists('Content-Type')) {
        die sprintf('Required Content-Type header. %s %s', $env->{REQUEST_METHOD}, $env->{PATH_INFO});
    }

    # NOTE: the charset attribute is necessary to prevent XSS in HTML pages
    # https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#content-type
    if ($header->get('Content-Type') =~ qr!^text/html!i) {
        unless ($header->get('Content-Type') =~ qr!charset=!) {
            die sprintf('Required charset for text/html. %s %s', $env->{REQUEST_METHOD}, $env->{PATH_INFO})
        }
    }

    unless ($header->exists('Content-Security-Policy')) {
        $header->set('Content-Security-Policy', $self->content_security_policy)
    }

    unless ($header->exists('Strict-Transport-Security')) {
        $header->set('Strict-Transport-Security', $self->strict_transport_security)
    }

    unless ($header->exists('X-Content-Type-Options')) {
        $header->set('X-Content-Type-Options', $self->x_content_type_options)
    }

    unless ($header->exists('X-Download-Options')) {
        $header->set('X-Download-Options', $self->x_download_options)
    }

    unless ($header->exists('X-Frame-Options')) {
        $header->set('X-Frame-Options', $self->x_frame_options)
    }

    unless ($header->exists('X-Permitted-Cross-Domain-Policies')) {
        $header->set('X-Permitted-Cross-Domain-Policies', $self->x_permitted_cross_domain_policies)
    }

    unless ($header->exists('X-XSS-Protection')) {
        $header->set('X-XSS-Protection', $self->x_xss_protection)
    }

    unless ($header->exists('Referrer-Policy')) {
        $header->set('Referrer-Policy', $self->referrer_policy)
    }

    return $res;
}

1;
__END__

=encoding utf-8

=head1 NAME

Plack::Middleware::SecureHeaders - manage security headers with many safe defaults

=head1 SYNOPSIS

    use Plack::Builder;

    builder {
        enable 'SecureHeaders';
        $app;
    };

=head1 DESCRIPTION

This middleware manages HTTP headers to protect against XSS attacks, insecure connections, content type sniffing, etc.
NOTE: To protect against these attacks, sanitization of user input values and other protections are also required.

=head2 DEFAULT HEADERS

By default, the following HTTP headers are set:

    Content-Security-Policy: default-src 'self' https:; font-src 'self' https: data:; img-src 'self' https: data:; object-src 'none'; script-src https:; style-src 'self' https: 'unsafe-inline'
    Strict-Transport-Security: max-age=631138519
    X-Content-Type-Options: nosniff
    X-Download-Options: noopen
    X-Frame-Options: sameorigin
    X-Permitted-Cross-Domain-Policies: none
    X-XSS-Protection: 1; mode=block
    Referrer-Policy: 'strict-origin-when-cross-origin',

This default value refers to the following sites L<https://github.com/github/secure_headers#default-values>.

=head2 OPTIONS

Secure HTTP headers can be changed as follows:

    use Plack::Builder;

    builder {
        enable 'SecureHeaders',
            content_security_policy           => "default-src 'self'",
            strict_transport_security         => 'max-age=631138519; includeSubDomains',
            x_frame_options                   => 'DENY',
            x_permitted_cross_domain_policies => 'none',
            x_xss_protection                  => '1',
            referrer_policy                   => 'no-referrer',
        ;

        $app;
    };

=head1 FAQ

=over 4

=item How do you remove HTTP header?

Please set undef to HTTP header you want to remove:

    # sef undef
    $res->header('Content-Security-Policy', undef);

    $res->header('Content-Security-Policy')
    # => undef


=undef

=head1 SEE ALSO

=over 4

=item L<https://github.com/github/secure_headers>

=item L<https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html>

=back

=head1 LICENSE

Copyright (C) kfly8.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=head1 AUTHOR

kfly8 E<lt>kfly@cpan.orgE<gt>

=cut

