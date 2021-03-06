#!/usr/bin/perl
 
################################################################################
#
# nmap2csv.pl
#
# scan hosts listed in a text file and and create csv file with a summary
#
#
# v1.0 15/11/2013 - Josep Fontana - Initial version
# v2.0 19/11/2013 - Josep Fontana - rewritten in perl using nmap::parser
# v3.0 27/11/2013 - Josep Fontana - choose action (launch nmap scans and/or
#									parse xml files) and which ports to report
# v4.0 13/03/2014 - Josep Fontana - output reflects parameter -p
#                                   added smb-os-discovery column
# v4.1 28/03/2014 - Josep Fontana - cleaned new code and fixed option switches
# v4.2 11/05/2015 - Josep Fontana - added smb-hostname, sql version
#									and http title columns
#
# TODO: change output name, enable/disable columns at output
# 


################################################################################
# init and argument parsing
################################################################################

# if a CPAN module is not installed, run
# $ perl -MCPAN -e 'install MODULE'
use warnings;
use Nmap::Parser;
use NetAddr::IP;
use Getopt::Std;
$Getopt::Std::STANDARD_HELP_VERSION = 1;

my $green = "\e[32m"; # originally "\e[32;40m"
my $bold = "\e[1m";
my $normal = "\e[0m";

# get arguments at hash %options
#  my $thing = $argx || 'default_value';
#

my %options;
getopts( 'p:s:o:i:n:', \%options ) or HELP_MESSAGE();

if (!$options{s} && !$options{o}) {HELP_MESSAGE();}

if ($options{o} eq $options{i}) { print "\n $bold*** ERROR: input and output file is the same !!!$normal\n\n"; HELP_MESSAGE();}

my @scan_ports = $options{p} || "1-";
my $scan_options = $options{n} || undef;
scan($options{s},@scan_ports) if $options{s};

my @csv_ports = $options{p} || "s";
my $in_file = $options{i} || undef;
parse_xml($options{o},@csv_ports,$in_file) if $options{o};


################################################################################
# SCAN section
# scan(file, ports, options)
#      file: text file with the list of hosts (hostname or IP)
#            that should be scanned, one in each line
#      ports: ports to scan, default is all
#      options: nmap options
################################################################################
sub scan {
	my $n = 0;	# used to count scanned hosts
	my $file = $_[0] or HELP_MESSAGE();
	my $total = `wc -l <$file` + 1;	
	my $ports = $_[1];
	my $options = $_[2];
	
	# open file with the list of hosts to scan
	open IN, "<$file" or die " *** Can't open file $file: $!\n";

	# here we should find nmap executable
	# but it's normally there!
	my $nmap = "/cygdrive/c/Program\\ Files\\ \\(x86\\)/Nmap/nmap.exe";
	die "\n *** ERROR ***  nmap.exe was not found at /cygdrive/c/Program Files (x86)/Nmap/\n"
		unless (-e "/cygdrive/c/Program\ Files\ \(x86\)/Nmap/nmap.exe");
	
	
	print "\nScanning the $bold$total$normal hosts listed at $file...\n";
	
	# foreach $host
	#	$status = system "$nmap -p 1- -T4 -A --webxml -oX $host.xml $host 1>/dev/null 2>/dev/null"
	#    die "nmap crashed: $?" unless $status == 0;
	#	rewrite counter
	my $error_report = "";
	foreach $host (<IN>){
		$/ = "\r\n";
		chomp($host);

		print progress_bar( $n, $total, 60, '=', 'targets' );
		
		my $status;
		if (!defined $options)
		{
			$status = system "$nmap -p $ports -T4 -A --webxml -oX $host.xml $host >/dev/null 2>&1";
		} else
		{
			$status = system "$nmap $options --webxml -oX $host.xml $host >/dev/null 2>&1";
		}
			
		$error_report = "$error_report *** nmap crashed while scanning $bold$host$normal: $?\n" unless $status == 0;#
		$n = $n + 1;
		print progress_bar( $n, $total, 60, '=', 'targets' );
	}
	print "\n\n$error_report\n";

}


################################################################################
# PARSE function
# parse_xml(out, ports, files)
#			out: csv output filename
#			ports: port list array
#			file: input files, undef if all xml in directory
################################################################################
sub parse_xml {

	my $n = 0;	# used to count xml files
	my $np = new Nmap::Parser;
	my @xml_files;
	if (!defined $_[2])
	{
		@xml_files = <*.xml>;
	} else
	{
		@xml_files = @_[2..$#_];
	}
	my $total = scalar @xml_files;
	my $out = $_[0] or HELP_MESSAGE();
	
	# set the port list to write in the csv
	if ($_[1] eq "s")
	{
		# get the sorted list of open ports from the xml file(s)
		@ports = port_list('open',@xml_files);
		
		# if the list is empty, get the sorted list of CLOSED ports...
		if (scalar @ports eq 0) { @ports = port_list('closed',@xml_files); }
		
		# if the list is still empty, get the sorted list of FILTERED ports...
		if (scalar @ports eq 0) { @ports = port_list('filtered',@xml_files); }
		
		# if the list is still empty, use the default port list
		if (scalar @ports eq 0) { @ports = split(',', "80,443,1433,21,22,25,445,389,636"); }
	} elsif ($_[1] eq "d")
	{
		# default port list
		@ports = split(',',"80,443,1433,21,22,25,445,389,636");
	} else
	{
		# use the provided port list
		@ports = split(',',$_[1]);
	}
	
	# IP ranges for each site
	# this can be edited to add known networks
	# code needs to be edited at line 253 to fit the new ranges

	my $private1 = NetAddr::IP->new('192.168.0.0/16');
	my $private2 = NetAddr::IP->new('169.254.0.0/16');
	my $private3 = NetAddr::IP->new('172.16.0.0/12');
	my $private4 = NetAddr::IP->new('127.0.0.0/8');
	my $private5 = NetAddr::IP->new('10.0.0.0/8');

	open OUT, ">$out" or die " *** Can't write on file $out: $!\n";
	if ($_[1] eq "d")
	{
		# default headers for default ports
		print OUT "IP,Hostname,SMB-Hostname,SMB-FQDN,OS,SMB-OS,SMB-SQL,Location,Status,http,https,sql,ftp,ssh,smtp,netbios,ldap,ldaps\n";
	} else
	{
		# add 
		print OUT "IP,Hostname,SMB-Hostname,SMB-FQDN,OS,SMB-OS,SMB-SQL,HTTP title (TCP/80),Location,Status";
				#$ip,$hostname,$smb_hostname,$smb_fqdn,$os,$smb_os,$smb_sql,$http_title,$site,$status
		
		foreach $p (@ports)
		{
			my $header = getservbyport($p, 'tcp');
			if (defined $header) { print OUT ",$header ($p)"; }
			else { print OUT ",$p"; }
		}
		print OUT "\n";
	}


	# foreach file	
	#   foreach host
	#     foreach port_of_interest
	#       do things!
	print "\nParsing the $bold$total$normal xml files present at this directory...\n";
	foreach $xml_file (@xml_files) {

		$n = $n + 1;
		# open xml
		$np->parsefile($xml_file);

		# go through each host in the scan
		my @hosts = $np->all_hosts();
		
		# this xml file has no hosts, the target may be down
		if (! @hosts)
		{
			$xml_file =~ s/.xml//;
			print OUT ("$xml_file,Host is down,,N/A,N/A,N/A,N/A,N/A,,,,,,,,,\n");   # this might not work !!!
			next;
		}
		
		foreach $host (@hosts)
		{
			# get general information about the Nmap::Parser::Host
			my $ip = $host->addr();
			my $hostname = $host->hostname(); # careful, this is a list
			my $status = $host->status();
			
			# standard OS detection
			my $os = ($host->os_sig())->name();
			# if there's nothing now we don't have information on the OS
			if (defined $os)
			{
				$os =~ s/\r//;
				$os =~ s/\n//;
				$os =~ s/,//g;
				$os =~ s/^\s+|\s+$//g;
			}else 
			{
				$os = "N/A";
			}
			

			# if we have information from smb-os-discovery, take it
			my $smb_os_href = ($host->hostscripts("smb-os-discovery"));
			my $smb_os_discovery = $smb_os_href->{'output'} || undef;  # will it work? :^P
			
			#get OS version from SMB script
			my $smb_os = $smb_os_discovery;
			if (defined $smb_os)
			{
				# parse result of smb-os-discovery
				$smb_os =~ s/\r//;
				$smb_os =~ s/\n//;
				$smb_os =~ s/,//g;
				$smb_os =~ /\n/;
				$smb_os = $`; #everything before previous match
				$smb_os =~ /OS: /;
				$smb_os = $'; # everything after previous match
				$smb_os =~ s/^\s+|\s+$//g; # remove leading and trailing spaces
			} else { $smb_os = "N/A";}
			
			#get HOSTNAME version from SMB script
			my $smb_hostname = $smb_os_discovery;
			if (defined $smb_hostname)
			{
				# parse result of smb-os-discovery
				$smb_hostname =~ s/\r//g;
				$smb_hostname =~ s/\n//g;
				$smb_hostname =~ s/,//g;
				$smb_hostname =~ /NetBIOS computer name\: /;
				$smb_hostname = $';
				$_ = $smb_hostname;
				if (/Workgroup\:/)
				{
					$smb_hostname =~ /Workgroup\: /;
					$smb_hostname = $`;
				} else
				{
					$smb_hostname =~ /  Domain name\: /;
					$smb_hostname = $`;
				}
				$smb_hostname =~ s/^\s+|\s+$//g; # remove leading and trailing spaces
			} else { $smb_hostname = "N/A";}
			
			#get FQDN version from SMB script
			my $smb_fqdn = $smb_os_discovery;
			if (defined $smb_fqdn)
			{
				# parse result of smb-os-discovery
				$smb_fqdn =~ s/\r//g;
				$smb_fqdn =~ s/\n//g;
				$smb_fqdn =~ s/,//g;
				$smb_fqdn =~ /  System time\: /;
				$smb_fqdn = $`;
				#$smb_fqdn_fallback = $smb_fqdn;
				$_ = $smb_fqdn;
				if (/FQDN\:/)
				{
					$smb_fqdn =~ /FQDN\: /;
					$smb_fqdn = $';
				} else
				{
					$smb_fqdn =~ /Workgroup\: /;
					$smb_fqdn = "(Workgroup) " . $';
				}	
				
				$smb_fqdn =~ s/^\s+|\s+$//g; # remove leading and trailing spaces
				

			} else { $smb_fqdn = "N/A";}
			
			
			# if we have information from ms-sql-info, take it
			my $ms_sql_info = ($host->hostscripts("ms-sql-info"));
			my $smb_sql = $ms_sql_info->{'output'} || undef;
			if (defined $smb_sql)
			{
				# parse result of ms-sql-info
				$smb_sql =~ s/\r//g;
				$smb_sql =~ s/\n//g;
				$smb_sql =~ s/,//g;

                                # NEW CODE - tested with nmap 7 code
                                $smb_sql =~ /Version: /; # to avoid the "Instance name" chunk
                                $smb_sql = $';
                                $smb_sql =~ /name:/;
                                $smb_sql = $';
                                $smb_sql =~ /  /; # there *should* not be more than one space in the product/version string
                                $smb_sql = $`;

                                # OLD CODE - does not seem to work well with nmap 7 output
                                #$smb_sql =~ /Version\: /;
                                #$smb_sql = $';
                                #$smb_sql =~ / Product\: /;
                                #$smb_sql = $`;
                                #$_ = $smb_sql;
                                #if (/ Version number\: /)
                                #{
                                #       $smb_sql =~ / Version number\: /;
                                #       $smb_sql = $`;
                                #}

				$smb_sql =~ s/^\s+|\s+$//g; # remove leading and trailing spaces
			} else { $smb_sql = "N/A";}
			
			
			# if we have port 80 open get information from http-title and put it into $http_title
			my $http_title = '';
			if ($host->tcp_port_state(80) ~~ 'open')
			{
#				if ('http-title' ~~ $host->tcp_service(80)->scripts())
#				{
					my $http_title_script = $host->tcp_service(80)->scripts("http-title");
					my $http_title_output = $http_title_script->{'output'} || undef;
					if (defined $http_title_output)
					{
						$_ = $http_title_output;
						if ( m/^Did not follow/)
						{
							$http_title = $http_title_output;
						} else 
						{
							#$http_title =~ /Requested resource was /;
							#$http_title = $`;
							$http_title = $http_title_output;
							if ($http_title_output =~ m/Requested resource was /)
							{
								$http_title = $`;
							}
						}
						
						# cleaning before finishing with this string
						$http_title =~ s/\n//g;
						$http_title =~ s/\r//g;
						$http_title =~ s/,//g;
						$http_title =~ s/^\s+|\s+$//g; # remove leading and trailing spaces
						
					} else
					{
#						$http_title = "N/A - could not get output from http-title script !!!";
#					}
#				} else
#				{
					$http_title = "N/A - http-title script did not run";
				}
			} else
			{
				$http_title = "N/A - Port closed";
			}
			
			
			
			# find the site
			my $site = "Internet";
			{
				my $ip = new NetAddr::IP $ip;
				if ($ip->within($private1))
				{
					$site = "Private 192.168.0.0/16";
				} elsif ($ip->within($private2))
				{
					$site = "Private 169.254.0.0/16";
				} elsif ($ip->within($private3))
				{
					$site = "Private 172.16.0.0/12";
				} elsif ($ip->within($private4))
				{
					$site = "Private 127.0.0.0/8";
				} elsif ($ip->within($private5))
				{
					$site = "Private 10.0.0.0/8";
				}	$site = "Private";
			}
			print OUT ("$ip,$hostname,$smb_hostname,$smb_fqdn,$os,$smb_os,$smb_sql,$http_title,$site,$status");
			
			# go through the ports of interest
			foreach $port (@ports)
			{
				# get the Nmap::Parser::Host::Service
				my $service = $host->tcp_service($port);
				
				# get the relevant information
				my $state = $host->tcp_port_state($port) || ''; # safe for non opened ports
				my $product = $service->product() || '';
				my $version = $service->version() || '';
				
				# and write the port information at the csv file
				if ($state eq "open")
				{
					print OUT (",$port");
					if ($version)
					{
						print OUT (" ($product $version)");
					}elsif ($product)
					{
						print OUT (" ($product)");
					}
				}else
				{
					print OUT (",");
				}
			}
			print OUT "\n";
		}
		
		print progress_bar( $n, $total, 60, '=', 'files' );
	}
	print progress_bar( $n, $total, 60, '=', 'files' );
	print "\n";
}



################################################################################
# PORT_LIST function
# ports = port_list(mode,xml_files)
#			ports: sorted array of unique port numbers
#			mode: nmap port status to filter
#			xml_files: input xml files
################################################################################
sub port_list
{
	my $np = new Nmap::Parser;
	my @ports = ( );
	my @all_ports = ( );
	my $mode = $_[0];
	my @xml_files = @_[1..$#_];
	
	foreach my $xml_file (@xml_files)
	{
		# open xml
		$np->parsefile($xml_file);

		# go through each host in the scan
		my @hosts = $np->all_hosts("up");
		foreach my $host (@hosts)
		{
			my @p = $host->tcp_ports($mode);

			if (scalar @p gt 0)
			{
				push @all_ports,@p;
			}
		}
	}
	
	# sorting and getting unique values
	if ($#all_ports gt 0)
	{
		# sort and store in a temporary array @p
		my @p = sort {$a <=> $b} @all_ports;
		my %seen = ( );
		
		@ports = grep { ! $seen{$_} ++ } @p;
	}

	return @ports;
}



# taken from http://oreilly.com/pub/h/943
sub progress_bar {
    my ( $got, $total, $width, $char, $object ) = @_;
    $width ||= 25; $char ||= '=';
    my $num_width = length $total;
    sprintf "|%-${width}s| Done %${num_width}s $object of %s ($green%.2f%%$normal)\r", 
        $char x (($width-1)*$got/$total). '>', 
        $got, $total, 100*$got/+$total;
}

sub VERSION_MESSAGE {
	print "\nnmap2csv.pl v4.2\n";
	exit();
}

sub HELP_MESSAGE {
	print "

Usage: nmap2csv.pl [-p port_list] [-n hosts_file]
			     [-x csv_out_file] [--help] [--version]

Create csv file from nmap XML output

	-i <input xml file(s)>	nmap xml file(s) to parse

	-o <output csv file>	create a csv summary of files provided by -i
				or all xml files present in the folder
				if -n is also specified it will still parse
				all xml files present in the current folder

	--help			this help message

	--version		show version\n";
	exit();
}
