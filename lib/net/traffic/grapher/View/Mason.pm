package net::traffic::grapher::View::Mason;

use strict;
use warnings;

use parent 'Catalyst::View::Mason';
use net::traffic::grapher;

__PACKAGE__->config(use_match => 0);
__PACKAGE__->config(comp_root => net::traffic::grapher->path_to(qw(root))->absolute->stringify );
__PACKAGE__->config(data_dir => net::traffic::grapher->path_to(qw(cache))->absolute->stringify );


=head1 NAME

net::traffic::grapher::View::Mason - Mason View Component for net::traffic::grapher

=head1 DESCRIPTION

Mason View Component for net::traffic::grapher

=head1 SEE ALSO

L<net::traffic::grapher>, L<HTML::Mason>

=head1 AUTHOR

Brad Lhotsky

=head1 LICENSE

This library is free software . You can redistribute it and/or modify it under
the same terms as perl itself.

=cut

1;
