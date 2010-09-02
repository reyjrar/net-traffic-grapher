use strict;
use warnings;
use Test::More;

BEGIN { use_ok 'Catalyst::Test', 'net::traffic::grapher' }
BEGIN { use_ok 'net::traffic::grapher::Controller::rrd' }

ok( request('/rrd')->is_success, 'Request should succeed' );
done_testing();
