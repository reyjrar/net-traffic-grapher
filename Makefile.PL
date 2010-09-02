#!/usr/bin/env perl
# IMPORTANT: if you delete this file your app will not work as
# expected.  You have been warned.
use inc::Module::Install;

name 'net-traffic-grapher';
all_from 'lib/net/traffic/grapher.pm';

requires 'Catalyst::Runtime' => '5.80019';
requires 'Catalyst::Plugin::ConfigLoader';
requires 'Catalyst::Plugin::Static::Simple';
requires 'Catalyst::Action::RenderView';
requires 'Catalyst::View::Mason';
requires 'Catalyst::View::RRDGraph';
requires 'Moose';
requires 'namespace::autoclean';
requires 'Config::General'; # This should reflect the config file format you've chosen
requires 'RRDs';
requires 'EV';
requires 'POE';
requires 'POE::Loop::EV';
requires 'POE::Component::Logger';
requires 'POE::Component::Pcap';
requires 'POE::Component::Daemon';
requires 'Path::Class';
requires 'NetPacket';
                 # See Catalyst::Plugin::ConfigLoader for supported formats
test_requires 'Test::More' => '0.88';
catalyst;

install_script glob('script/*.pl');
auto_install;
WriteAll;
