#! /usr/bin/env perl
# Copyright 2016-2018 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use OpenSSL::Test qw/:DEFAULT srctop_dir bldtop_dir/;
use OpenSSL::Test::Utils;
use File::Temp qw(tempfile);

#Load configdata.pm

BEGIN {
    setup("test_shlibload");
}
use lib srctop_dir('Configurations');
use lib bldtop_dir('.');
use platform;

plan skip_all => "Test only supported in a shared build" if disabled("shared");
plan skip_all => "Test is disabled on AIX" if config('target') =~ m|^aix|;
plan skip_all => "Test only supported in a dso build" if disabled("dso");

plan tests => 10;

my $libcrypto = platform->sharedlib('libcrypto');
my $libssl = platform->sharedlib('libssl');

sub run_shlibloadtest {
    (my $fh, my $filename) = tempfile();
    ok(run(test(["shlibloadtest", @_, $libcrypto, $libssl, $filename])),
       join(' ', ("running shlibloadtest", @_,"$filename")));
    ok(check_atexit($fh));
    unlink $filename;
}

# Each run_shlibloadtest runs two tests
run_shlibloadtest("-crypto_first");
run_shlibloadtest("-ssl_first");
run_shlibloadtest("-just_crypto");
run_shlibloadtest("-dso_ref");
run_shlibloadtest("-no_atexit");

sub check_atexit {
    my $fh = shift;
    my $data = <$fh>;

    return 1 if (defined $data && $data =~ m/atexit\(\) run/);

    return 0;
}
