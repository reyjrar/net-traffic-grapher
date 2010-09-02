package net::traffic::grapher::Controller::rrd;
use Moose;
use namespace::autoclean;
use File::Spec;
use File::Basename;
use Path::Class;
use File::Find::Rule;

BEGIN {extends 'Catalyst::Controller'; }

=head1 NAME

net::traffic::grapher::Controller::rrd - Catalyst Controller

=head1 DESCRIPTION

Catalyst Controller.

=head1 METHODS

=cut

my %_spans = (
	halfday => { start => 3600*12, step => 60 },
	day 	=> { start => 3600*24, step => 60 },
	week 	=> { start => 3600*24*7, step => 60 },
	month 	=> { start => 3600*24*30, step => 60 },
);


=head2 index

=cut

sub index :Path :Args(0) {
    my ( $self, $c ) = @_;

    $c->response->body('Matched net::traffic::grapher::Controller::rrd in rrd.');
}

sub rrd_base :Chained('/') :PathPart('rrd') :CaptureArgs(0) {
	my ($self,$c) = @_;
}

sub service_rrd :Chained('rrd_base') :PathPart('service') :CaptureArgs(1) {
	my ($self,$c,$service) = @_;

	# Untaint
	$service =~ s/[^a-z0-9]+//g;

	# Do we have files
	my @rrds = File::Find::Rule->file()->name( lc($service) . '.rrd' )->in( $c->stash->{rrd_base} );
	if( !@rrds ) {
		die "service_rrd($service): no data";
	}

	$c->stash->{service} = $service;
	$c->stash->{rrds} = \@rrds;
}

sub service_view :Chained('service_rrd') :PathPart('view') :Args(2) {
	my ($self,$c,$type,$span) = @_;

	my @rrds = @{ $c->stash->{rrds} };

	# Type Definition
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

	if( !exists $_defs{$type} ) {
		die "service_view($type): non-existant type";
	}
	if( !exists $_spans{$span} ) {
		die "service_view($span): unknown time span";
	}

	# Build out the Defintions & Artifacts
	my @defs = ();
	my @artifacts = ();
	foreach my $rrd (@rrds) {
		my @dirs = File::Spec->splitdir( dirname( $rrd ) );
		my $proto = pop @dirs;
		my $varname = join('_', $proto, $type);
		next unless exists $_defs{$type}->{$varname};
		my $info_ref = $_defs{$type}->{$varname};

		push @defs, qq{DEF:$varname=$rrd:$type:AVERAGE};
		push @artifacts, qq{AREA:$varname#$info_ref->{color}:$info_ref->{title}:STACK};
	}
	# Build the Time
	my $time = time;

	$c->stash->{graphopts} = {
		start => $time - $_spans{$span}->{start},
		end	=> $time,
		step => $_spans{$span}->{step},
		defs => \@defs,
		artifacts => \@artifacts,		
		title => $c->stash->{service} . ", past $span",
		'vertical-label' => $type,
	};

	# Display the graph
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
	$c->stash->{rrd_base} = $c->config->{rrd}{dir};
	if( ! -d $c->stash->{rrd_base} ) {
		die "rrd/dir not defined in config!";
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

