package net::traffic::grapher::Controller::rrd;
use Moose;
use namespace::autoclean;
use File::Spec;
use File::Basename;
use Path::Class;

BEGIN {extends 'Catalyst::Controller'; }

=head1 NAME

net::traffic::grapher::Controller::rrd - Catalyst Controller

=head1 DESCRIPTION

Catalyst Controller.

=head1 METHODS

=cut


=head2 index

=cut

sub index :Path :Args(0) {
    my ( $self, $c ) = @_;

    $c->response->body('Matched net::traffic::grapher::Controller::rrd in rrd.');
}

sub rrd_base :Chained('/') :PathPart('rrd') :CaptureArgs(0) {
	my ($self,$c) = @_;
}

sub syslog_data :Chained('rrd_base') :PathPart('syslog') :CaptureArgs(1) {
	my ( $self, $c, $srv ) = @_;
	my $dir = dir( File::Spec->catdir($c->stash->{datadir}, 'syslog') );

	my %file = ();

	my $abs = $dir->file($srv . '.rrd')->absolute->stringify;
	if( -f $abs ) {
		%file = (  name => $srv, file => $abs );
	}
	else {
		die "rrd_graph(syslog): unknown srv '$srv'";
	}

	$c->stash->{type} = 'syslog';
	$c->stash->{id} = $srv;
	$c->stash->{rrd} = \%file;
}

sub syslog_view :Chained('syslog_data') :PathPart('view') :Args(2) {
	my ( $self, $c, $type, $span ) = @_;

	my %_defs = (
		bytes => {
			tcp_bytes	=> { title => 'TCP Bytes', color => '66FF66' },
			udp_bytes	=> { title => 'UDP Bytes', color => 'FF6666' },
		},
		packets => {
			tcp_packets	=> { title => 'TCP Packets', color => '66FF66' },
			udp_packets	=> { title => 'UDP Packets', color => 'FF6666' },
		},
	);
	my $time = time;
	my %_spans = (
		halfday 	=> { start => $time - 3600*12, end => $time, step => 60 },
		day 	=> { start => $time - 3600*24, end => $time, step => 60 },
		week 	=> { start => $time - 3600*24*7, end => $time, step => 60 },
		month 	=> { start => $time - 3600*24*30, end => $time, step => 60 },
	);

	# Defaults
	if( !defined $type || !exists $_defs{$type} ) {
		$type = 'bytes';
	}
	if( !defined $span || !exists $_spans{$span} ) {
		$span = 'day';
	}

	
	# Build Lines	
	my @defs = ();
	my @artifacts = ();
	my $rrd = $c->stash->{rrd};
	foreach my $var ( keys %{ $_defs{$type} } ) {
		my $info_ref = $_defs{$type}->{$var};
		push @defs, qq{DEF:$var=$rrd->{file}:$var:AVERAGE};
		push @artifacts, qq{AREA:$var#$info_ref->{color}:$info_ref->{title}:STACK};
	}

	$c->stash->{graphopts} = {
		%{ $_spans{$span} },
		defs => \@defs,
		artifacts => \@artifacts,		
		title => $c->stash->{type} . ' - ' . $c->stash->{id} . ", past $span",
		'vertical-label' => $type,
	};

	$c->detach('/rrd/display_graph');

}

sub display_graph :Private {
	my ( $self, $c ) = @_;

	my $opts = $c->stash->{graphopts};
	$c->stash->{graph} = [
			'--color' => 'BACK#FFFFFF',
			'--color' => 'CANVAS#FFFAF0',
			'--color' => 'GRID#CCCCCC',
			'--color' => 'MGRID#CCCCCC',
			'--color' => 'FONT#000000',
			'--color' => 'ARROW#FF0000',
			'--color' => 'FRAME#000000',
			'--title' => $opts->{title},
			'--vertical-label' => $opts->{'vertical-label'},
			'--start' => $opts->{start},
			'--step' => $opts->{step},
			@{ $opts->{defs} },
			@{ $opts->{artifacts} },
			"HRULE:0#0000FF"
	];
}

=head2 auto

Setup Defaults for the RRD Graphing

=cut

sub auto :Private {
	my ( $self, $c) = @_;


	$c->stash->{current_view} = 'RRDGraph';
	$c->stash->{datadir} = $c->config->{rrd}{datadir};
	if( ! -d $c->stash->{datadir} ) {
		die "rrd/datadir not defined in config!";
	}
	return 1;
}


=head1 AUTHOR

Brad Lhotsky

=head1 LICENSE

This library is free software. You can redistribute it and/or modify
it under the same terms as Perl itself.

=cut

__PACKAGE__->meta->make_immutable;

