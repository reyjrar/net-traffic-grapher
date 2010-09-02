#!/usr/bin/perl
#
# Use Net::Pcap to analyze traffic for interesting patterns
#

use strict;
use warnings;

#
# File Handling
use FindBin;
use File::Basename;
use File::Spec;
use Config::General qw(ParseConfig);

#
# Packet Parsing
use NetPacket::Ethernet qw(:strip :types);
use NetPacket::IP qw(:strip :protos);
use NetPacket::UDP;
use NetPacket::TCP;

#
# RRD
use RRDs;

#
# POE Environment
use POE qw(
	Component::Daemon
	Component::Logger
	Component::Pcap
);

# Read the Config File
my $CONFIG_FILE = File::Spec->catfile( "$FindBin::Bin", "..", "net_traffic_grapher.conf");
#
# Application Settings
my %CONFIG = ParseConfig( $CONFIG_FILE );
$CONFIG{stats}=15;


#
# Pcap Options
my %PCAP = %{ $CONFIG{pcap} };
my %SERVICES = %{ $CONFIG{services} };

#POE::Component::Daemon->spawn( detach => 1, babysit => 600, max_children => 5 );

# Logger
my $log_sess = POE::Component::Logger->spawn(
	Alias		=> 'log',
	ConfigFile	=> $CONFIG{log_cfg},
);

# Processor
my $proc_sess = POE::Session->create(
	inline_states	=> {
		_start			=> \&start_processor,
		_stop			=> \&stop_processor,
		handle_packet	=> \&handle_packet,
		rrd_step		=> \&rrd_step,
		show_stats		=> \&show_stats,
	},
);
POE::Kernel->run;

exit 0;

#------------------------------------------------------------------------#
# Start the Processor
sub start_processor {
	my ($kernel,$heap) = @_[KERNEL,HEAP];

	$kernel->alias_set('processor');

	# PCAP Engine
	my $pcap_sess =	POE::Component::Pcap->spawn(
			Alias		=> 'pcap',
			Device		=> $PCAP{device},
			Dispatch	=> 'handle_packet',
			Session		=> 'processor',
	);

	$kernel->post( pcap => open_live => @PCAP{qw(device snaplen promisc timeout)} );
	#$kernel->post( pcap => set_filter => q{tcp or udp} );
	$kernel->post( pcap => 'run' );


	$kernel->post( 'log' => 'notice' => '(traffic_gather) Started up.');

	#
	# Setup the RRD directories:
	my @dirs = File::Spec->splitdir( $CONFIG{rrd}->{dir} );
	if ( ! -d $CONFIG{rrd}->{dir} ) {
		my @path = ();
		foreach my $dir (@dirs) {
			my $dirname = File::Spec->catdir( @path, $dir );
			mkdir( $dirname, 0755 ) unless -d $dirname;
			push @path,$dir;
		}
	}
	$kernel->sig( INT => 'stop_processor' );
	$kernel->delay_add('show_stats', $CONFIG{stats}) if $CONFIG{stats};
	$kernel->delay_add('rrd_step', 60);
}
#------------------------------------------------------------------------#

#------------------------------------------------------------------------#
# stop the processor
sub stop_processor {
	my ($kernel,$heap) = @_[KERNEL,HEAP];

	$kernel->post( 'log' => 'notice' => "(traffic_gather) $0 shutting down");
	
	# Stop pcap
	$kernel->post( 'pcap' => 'shutdown' );

	$kernel->stop;
}
#------------------------------------------------------------------------#

#------------------------------------------------------------------------#
sub handle_packet {
	my ($kernel,$heap,$packets) = @_[KERNEL,HEAP,ARG0];

	foreach my $inst ( @{ $packets } )  {
		my ($hdr, $pkt) = @{ $inst };
		next unless defined $hdr;

		increment_stat('packets', $heap);
	
		if( exists $PCAP{offset} && $PCAP{offset} > 0 ) {
			$pkt = substr( $pkt, $PCAP{offset} );
		}
		my $eth_pkt = NetPacket::Ethernet->decode( $pkt );

		if( $eth_pkt->{type} != ETH_TYPE_IP ) {
			increment_stat('nonip', $heap);
			next;
		}
		# This is an IP Packet
		my $ip_pkt  = NetPacket::IP->decode( $eth_pkt->{data} );
		increment_stat('ip', $heap );

		#
		# IP Protocol Specifics
		if($ip_pkt->{proto} == IP_PROTO_UDP ) {
			parse_udp( $pkt, $ip_pkt, $heap );
		}
		elsif( $ip_pkt->{proto} == IP_PROTO_TCP ) {
			parse_tcp( $pkt, $ip_pkt, $heap );
		}
		else { 
			increment_stat('proto' . $ip_pkt->{proto}, $heap);
		}
	}
}
#------------------------------------------------------------------------#
sub show_stats {
	my( $kernel, $heap ) = @_[KERNEL,HEAP];

	if( !exists  $heap->{stats}  ) {
		$kernel->post( log => notice => 'no packets.' );
	}
	else {

		# Copy the stats:
		my %stats = %{ delete $heap->{stats} };
	
		# Pair
		my @pairs = ();
		while( my ($k,$v) = each %stats ) {
			push @pairs, "$k=$v";
		}
		# Log:
		$kernel->post( 'log' => info => 'STATS: ' . join(',', @pairs) );		
	}	
	# Redo Stats
	$kernel->delay_add( 'show_stats', $CONFIG{stats} );
}

#------------------------------------------------------------------------#


#------------------------------------------------------------------------#
sub parse_udp {
	my ($orig, $ip, $heap) = @_;

	#
	# udp packet breakdown
	my $udp = NetPacket::UDP->decode( $ip->{data} );
	increment_stat('udp', $heap);

	my $service = '';
	if( exists $SERVICES{udp}->{$udp->{src_port}} ) {
		$service = $SERVICES{udp}->{$udp->{src_port}};
	}
	elsif( exists $SERVICES{udp}->{$udp->{dest_port}} ) {
		$service = $SERVICES{udp}->{$udp->{dest_port}};
	}
	else {
		$service = 'other';
	}
	count_packet( $heap, 'udp', $service, length $orig );
	increment_stat( 'udp::'.$service, $heap );
	
	return;
}
#------------------------------------------------------------------------#

#------------------------------------------------------------------------#
sub parse_tcp {
	my ($orig, $ip, $heap) = @_;

	#
	# tcp packet breakdown
	my $tcp = NetPacket::TCP->decode( $ip->{data} );
	increment_stat('tcp', $heap);

	my $service = '';
	if( exists $SERVICES{tcp}->{$tcp->{src_port}} ) {
		$service = $SERVICES{tcp}->{$tcp->{src_port}};
	}
	elsif( exists $SERVICES{tcp}->{$tcp->{dest_port}} ) {
		$service = $SERVICES{tcp}->{$tcp->{dest_port}};
	}
	else {
		$service = 'other';
	}
	count_packet( $heap, 'tcp', $service, length $orig );
	increment_stat( 'tcp::'.$service, $heap );
				
	return;
}

#------------------------------------------------------------------------#
sub rrd_step {
	my ($kernel,$heap) = @_[KERNEL,HEAP];

	my %counters = %{ delete $heap->{counters} };
	#
	# Update Traffic
	foreach my $proto (keys %counters ) {
		my $info_ref = $counters{$proto}->{__TOTAL__};
		rrd_update( [ $proto ], $info_ref);
		foreach my $svc (keys %{ $counters{$proto} }) {
			next if $svc eq '__TOTAL__';
			rrd_update( [ $proto, $svc ], $counters{$proto}->{$svc} );
		}
	}

	$kernel->delay('rrd_step', 60);
}
#------------------------------------------------------------------------#

#------------------------------------------------------------------------#
sub rrd_update {
	my ($path,$info) = @_;

	my $RRD = rrd_create( $path );
	my $update_str = join( ':',
			time,
			$info->{packets} || 0,
			$info->{bytes} || 0,
	);
	$poe_kernel->post('log' => 'debug' => "(traffic_gather) rrd_udpdate(): $RRD -> $update_str");
	RRDs::update $RRD, $update_str;
	my $err = RRDs::error;
	if( $err ) {
		$poe_kernel->post('log' => 'error' => "(traffic_gather) rrd_udpdate(): $RRD($update_str) $err");
	}
}
#------------------------------------------------------------------------#

#------------------------------------------------------------------------#
sub rrd_create {
	my ($pref)= @_;

	# Copy the Path array for local manipulation
	my @path = @$pref;

	#
	# Last part of the path is the rrd file name.
	my $rrd_file = pop(@path) . '.rrd';

	#
	# Build out the Path
	my @build_path = ( $CONFIG{rrd}->{dir} );
	foreach my $sub ( @path ) {
		my $dirname = File::Spec->catdir( @build_path, $sub );
		mkdir( $dirname, 0755 ) unless -d $dirname;
		push @build_path,$sub;
	}
	# Build the Full Path
	my $RRD = File::Spec->catfile( @build_path, $rrd_file );
	# Return the RRD if it already exists:
	return $RRD if -e $RRD;

	# RRD Options:
	my @opts = (
		'--step', 60,
		'DS:packets:GAUGE:600:0:U',
		'DS:bytes:GAUGE:600:0:U',
		'RRA:AVERAGE:0.5:1:576',
		'RRA:AVERAGE:0.5:8:576',
		'RRA:AVERAGE:0.5:32:576',
		'RRA:AVERAGE:0.5:372:576',
	);
	RRDs::create $RRD, @opts;
	my $err = RRDs::error;
	if( $err ) {
		$poe_kernel->post('log' => 'error' => "(traffic_gather) create_rrd() problem creating $RRD: $err");
	}
	return $RRD;
}
#------------------------------------------------------------------------#
sub count_packet {
	my ($heap,$proto,$service,$size) = @_;

	if( !exists $heap->{counters} ) {
		$heap->{counters} = {};
	}
	if( !exists $heap->{counters}{$proto} ) {
		$heap->{counters}{$proto} = {
			__TOTAL__ => {
				packets => 0, bytes => 0
			},
		};
	}
	if( !exists $heap->{counters}{$proto}{$service} ) {
		$heap->{counters}{$proto}{$service} = {
			packets => 0,
			bytes => 0,
		};
	}
	$heap->{counters}{$proto}{__TOTAL__}{packets}++;
	$heap->{counters}{$proto}{__TOTAL__}{bytes} += $size;
	$heap->{counters}{$proto}{$service}{packets}++;
	$heap->{counters}{$proto}{$service}{bytes} += $size;
}
#------------------------------------------------------------------------#
sub increment_stat {
	my ($name,$heap) = @_;

	if( !exists $heap->{stats} || ref $heap->{stats} ne 'HASH' ) {
		$heap->{stats} = {};
	}
	if( !exists $heap->{stats}{$name} ) {
		$heap->{stats}{$name} = 0;
	}
	$heap->{stats}{$name}++;
}
