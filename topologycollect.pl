#!/usr/bin/perl
use strict;
use warnings;
use POSIX qw(strftime);
use Data::Dumper;

my $LOGFILE = "${0}.log";
my $T3 = "/root/HFCNOC_T3";
my $SSHKEY = "$T3/SCRIPT_USER_CREDS__do_not_remove/.ssh/id_rsa";
my $COLLECTORDIR = "/usr/local/t3/collector";
#my $COLLECTORDIR = ".";
my $TODAY = strftime("%Y%m%d", localtime());
my %TYPE = (
    node => {
        server => "emdpc0101001pr",
        dir => sprintf( '%s/DNS_CMTS_LIST', $T3 ),
        file => sprintf( 'topology_%s.txt', $TODAY ),
        slink => 'topology.txt',
    },
    lni => {
        server => "emdrf0101002pr",
        dir => "/sit2site1/Exports/SAC",
        file => "servAssureData.out",
        dfile => sprintf( 'servAssureData_%s.out', $TODAY ),
        slink => 'servAssureData.out',
    },
);

my $Logfh;
sub log {
    my @msg = @_;
    my $now = strftime "%Y-%m-%d %H:%M:%S", localtime();

    unless ($Logfh) {
        open $Logfh, '>>', $LOGFILE or die "Could not open logfile, $!";
        &info("---------------------- Sourcing topology details -------------------------");
    }

    print $Logfh join( " ", $now, @msg, "\n" );
}

END {
    close $Logfh;
}

sub info { &log('INFO', @_); }
sub warn { &log('WARN', @_); }
sub crit { &log('CRIT', @_); }


#
# Main

for my $type (keys %TYPE) {
    my $msgfile = $TYPE{$type}{file};
    my $destination;

    if (defined $TYPE{$type}{dfile}) {
        $destination = "$COLLECTORDIR/". $TYPE{$type}{dfile};
        $msgfile .= " (to: $TYPE{$type}{dfile})";
    }
    else {
        $destination = "$COLLECTORDIR/". $TYPE{$type}{file};
    }

    my $scp = sprintf "scp -q -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i %s %s:%s/%s %s",
                $SSHKEY, $TYPE{$type}{server}, $TYPE{$type}{dir}, $TYPE{$type}{file}, $destination;

    &info("Copying over file: $msgfile, from: $TYPE{$type}{server}");
    qx($scp);

    &info("Removing stale symlink: $TYPE{$type}{slink}");
    qx(rm -f $COLLECTORDIR/$TYPE{$type}{slink});

    &warn("Could not update symlink: $TYPE{$type}{slink}, stale data will be used")
        if -l "$COLLECTORDIR/$TYPE{$type}{slink}";

    &info("Updating symlink: $TYPE{$type}{slink}, to: $destination");
    qx(ln -s $destination $COLLECTORDIR/$TYPE{$type}{slink});

    &crit("Could not create symlink to $TYPE{$type}{slink}")
        unless -l "$COLLECTORDIR/$TYPE{$type}{slink}";
}

# here should really only be two files
my @remove;
for my $glob ('*.txt', '*.out') {
    push @remove, qx(find $COLLECTORDIR -type f -name '$glob' -mtime +3 -print);
}
chomp(@remove);

qx(rm -f @remove);

#my $rmsg = "Removing files: ". (@remove || "None");
#@remove > 1 ? &warn($rmsg) : &info($rmsg);
my $rmsg = "Removing files: ". (@remove ? join(', ', @remove) : "None");
@remove > 2 ? &warn($rmsg) : &info($rmsg);
