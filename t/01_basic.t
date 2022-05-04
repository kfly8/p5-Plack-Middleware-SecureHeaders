use strict;
use warnings;
use Test::More;
use Plack::Test;
use Plack::Builder;
use HTTP::Request::Common;

subtest 'no Content-Type' => sub {
    my $app = builder {
        enable 'SecureHeaders';
        sub { [ 200, [ ], ['HELLO WORLD'] ] };
    };

    test_psgi $app, sub {
        my $cb  = shift;
        my $res = $cb->(GET '/');
        is $res->code, 500, 'response status 500';
        like $res->content, qr/^Required Content-Type header/, 'content include error message';
    };
};

subtest 'text/html required charset' => sub {
    my $app = builder {
        enable 'SecureHeaders';
        sub { [ 200, ['Content-Type' => 'text/html'], ['HELLO WORLD'] ] };
    };

    test_psgi $app, sub {
        my $cb  = shift;
        my $res = $cb->(GET '/');
        is $res->code, 500, 'response status 500';
        like $res->content, qr/^Required charset for text\/html/, 'content include error message';
    };

    my $app_with_charset = builder {
        enable 'SecureHeaders';
        sub { [ 200, ['Content-Type' => 'text/html; charset=utf-8'], ['HELLO WORLD'] ] };
    };

    test_psgi $app_with_charset, sub {
        my $cb  = shift;
        my $res = $cb->(GET '/');
        is $res->code, 200, 'response status 200';
        is $res->content, 'HELLO WORLD';
    };
};

subtest 'default secure headers' => sub {
    my $app = builder {
        enable 'SecureHeaders';
        sub { [ 200, ['Content-Type' => 'text/plain'], ['HELLO WORLD'] ] };
    };

    test_psgi $app, sub {
        my $cb  = shift;
        my $res = $cb->(GET '/');
        is $res->code, 200, 'response status 200';

        is_deeply [split '; ', $res->header('Content-Security-Policy')], [
            "default-src 'self' https:",
            "font-src 'self' https: data:",
            "img-src 'self' https: data:",
            "object-src 'none'",
            "script-src https:",
            "style-src 'self' https: 'unsafe-inline'",
        ], 'Content-Security-Policy';

        is $res->header('Strict-Transport-Security'),         'max-age=631138519',               'Strict-Transport-Security';
        is $res->header('X-Content-Type-Options'),            'nosniff',                         'X-Content-Type-Options';
        is $res->header('X-Download-Options'),                'noopen',                          'X-Download-Options';
        is $res->header('X-Frame-Options'),                   'SAMEORIGIN',                      'X-Frame-Options';
        is $res->header('X-Permitted-Cross-Domain-Policies'), 'none',                            'X-Permitted-Cross-Domain-Policies';
        is $res->header('X-XSS-Protection'),                  '1; mode=block',                   'X-XSS-Protection';
        is $res->header('Referrer-Policy'),                   'strict-origin-when-cross-origin', 'Referrer-Policy';
    };
};


subtest 'not default secure headers' => sub {
    my $app = builder {
        enable 'SecureHeaders';
        sub { [ 200, [
            'Content-Type' => 'text/plain',
            'Content-Security-Policy'           => "default-src 'self'",
            'Strict-Transport-Security'         => 'max-age=31536000; includeSubDomains',
            'X-Content-Type-Options'            => 'nosniff',
            'X-Download-Options'                => 'noopen',
            'X-Frame-Options'                   => 'DENY',
            'X-Permitted-Cross-Domain-Policies' => 'master-only',
            'X-XSS-Protection'                  => '1',
            'Referrer-Policy'                   => 'no-referrer',
        ], ['HELLO WORLD'] ] };
    };

    test_psgi $app, sub {
        my $cb  = shift;
        my $res = $cb->(GET '/');
        is $res->code, 200, 'response status 200';

        is $res->header('Content-Security-Policy'),           "default-src 'self'",                  'Content-Security-Policy';
        is $res->header('Strict-Transport-Security'),         'max-age=31536000; includeSubDomains', 'Strict-Transport-Security';
        is $res->header('X-Content-Type-Options'),            'nosniff',                             'X-Content-Type-Options';
        is $res->header('X-Download-Options'),                'noopen',                              'X-Download-Options';
        is $res->header('X-Frame-Options'),                   'DENY',                                'X-Frame-Options';
        is $res->header('X-Permitted-Cross-Domain-Policies'), 'master-only',                         'X-Permitted-Cross-Domain-Policies';
        is $res->header('X-XSS-Protection'),                  '1',                                   'X-XSS-Protection';
        is $res->header('Referrer-Policy'),                   'no-referrer',                         'Referrer-Policy';
    };
};


subtest 'Content-Security-Policy option' => sub {
    my $value = "default-src 'self'";

    my $app = builder {
        enable 'SecureHeaders', content_security_policy => $value;
        sub { [ 200, ['Content-Type' => 'text/plain'], ['HELLO WORLD'] ] };
    };

    test_psgi $app, sub {
        my $cb  = shift;
        my $res = $cb->(GET '/');
        is $res->header('Content-Security-Policy'), $value;
    };
};

subtest 'Strict-Transport-Security option' => sub {
    my $value = "max-age=31536000; includeSubDomains";

    my $app = builder {
        enable 'SecureHeaders', strict_transport_security => $value;
        sub { [ 200, ['Content-Type' => 'text/plain'], ['HELLO WORLD'] ] };
    };

    test_psgi $app, sub {
        my $cb  = shift;
        my $res = $cb->(GET '/');
        is $res->header('Strict-Transport-Security'), $value;
    };
};

subtest 'X-Frame-Options option' => sub {
    my $value = "DENY";

    my $app = builder {
        enable 'SecureHeaders', x_frame_options => $value;
        sub { [ 200, ['Content-Type' => 'text/plain'], ['HELLO WORLD'] ] };
    };

    test_psgi $app, sub {
        my $cb  = shift;
        my $res = $cb->(GET '/');
        is $res->header('X-Frame-Options'), $value;
    };
};

subtest 'X-Permitted-Cross-Domain-Policies option' => sub {
    my $value = "master-only";

    my $app = builder {
        enable 'SecureHeaders', x_permitted_cross_domain_policies => $value;
        sub { [ 200, ['Content-Type' => 'text/plain'], ['HELLO WORLD'] ] };
    };

    test_psgi $app, sub {
        my $cb  = shift;
        my $res = $cb->(GET '/');
        is $res->header('X-Permitted-Cross-Domain-Policies'), $value;
    };
};

subtest 'X-XSS-Protection option' => sub {
    my $value = "1";

    my $app = builder {
        enable 'SecureHeaders', x_xss_protection => $value;
        sub { [ 200, ['Content-Type' => 'text/plain'], ['HELLO WORLD'] ] };
    };

    test_psgi $app, sub {
        my $cb  = shift;
        my $res = $cb->(GET '/');
        is $res->header('X-XSS-Protection'), $value;
    };
};

subtest 'Referrer-Policy option' => sub {
    my $value = "no-referrer";

    my $app = builder {
        enable 'SecureHeaders', referrer_policy => $value;
        sub { [ 200, ['Content-Type' => 'text/plain'], ['HELLO WORLD'] ] };
    };

    test_psgi $app, sub {
        my $cb  = shift;
        my $res = $cb->(GET '/');
        is $res->header('Referrer-Policy'), $value;
    };
};

done_testing;
