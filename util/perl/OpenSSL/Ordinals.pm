#! /usr/bin/env perl
# Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

package OpenSSL::Ordinals;

use strict;
use warnings;
use Carp;
use Scalar::Util qw(blessed);

use constant {
    # "magic" filters, see the filters at the end of the file
    F_NAME      => 1,
    F_NUMBER    => 2,
};

=head1 NAME

OpenSSL::Ordinals - a private module to read and walk through ordinals

=head1 SYNOPSIS

  use OpenSSL::Ordinals;

  my $ordinals = OpenSSL::Ordinals->new(from => "foo.num");
  # or alternatively
  my $ordinals = OpenSSL::Ordinals->new();
  $ordinals->load("foo.num");

  foreach ($ordinals->items(comparator => by_name()) {
    print $_->name(), "\n";
  }

=head1 DESCRIPTION

This is a OpenSSL private module to load an ordinals (F<.num>) file and
write out the data you want, sorted and filtered according to your rules.

An ordinals file is a file that enumerates all the symbols that a shared
library or loadable module must export.  Each of them have a unique
assigned number as well as other attributes to indicate if they only exist
on a subset of the supported platforms, or if they are specific to certain
features.

The unique numbers each symbol gets assigned needs to be maintained for a
shared library or module to stay compatible with previous versions on
platforms that maintain a transfer vector indexed by position rather than
by name.  They also help keep information on certain symbols that are
aliases for others for certain platforms, or that have different forms
on different platforms.

=head2 Main methods

=over  4

=cut

=item B<new> I<%options>

Creates a new instance of the C<OpenSSL::Ordinals> class.  It takes options
in keyed pair form, i.e. a series of C<key =E<gt> value> pairs.  Available
options are:

=over 4

=item B<from =E<gt> FILENAME>

Not only create a new instance, but immediately load it with data from the
ordinals file FILENAME.

=back

=cut

sub new {
    my $class = shift;
    my %opts = @_;

    my $instance = {
        filename        => undef, # File name registered when loading
        loaded_maxnum   => 0,     # Highest allocated item number when loading
        loaded_contents => [],    # Loaded items, if loading there was
        maxnum          => 0,     # Current highest allocated item number
        contents        => [],    # Items, indexed by number
        name2num        => {},    # Name to number dictionary
        aliases         => {},    # Aliases cache.
        stats           => {},    # Statistics, see 'sub validate'
        currversion     => $opts{version} // '*', # '*' is for "we don't care"
        debug           => $opts{debug},
    };
    bless $instance, $class;

    $instance->load($opts{from}) if defined($opts{from});

    return $instance;
}

=item B<$ordinals-E<gt>load FILENAME>

Loads the data from FILENAME into the instance.  Any previously loaded data
is dropped.

Two internal databases are created.  One database is simply a copy of the file
contents and is treated as read-only.  The other database is an exact copy of
the first, but is treated as a work database, i.e. it can be modified and added
to.

=cut

sub load {
    my $self = shift;
    my $filename = shift;

    croak "Undefined filename" unless defined($filename);

    my @tmp_contents = ();
    my %tmp_name2num = ();
    my $max_num = 0;
    open F, '<', $filename or croak "Unable to open $filename";
    while (<F>) {
        s|\R$||;                # Better chomp
        s|#.*||;
        next if /^\s*$/;

        my $item = OpenSSL::Ordinals::Item->new(from => $_);

        my $num = $item->number();
        croak "Disordered ordinals, $num < $max_num"
            if $num < $max_num;
        $max_num = $num;

        push @{$tmp_contents[$item->number()]}, $item;
        $tmp_name2num{$item->name()} = $item->number();
    }
    close F;

    $self->{contents} = [ @tmp_contents ];
    $self->{name2num} = { %tmp_name2num };
    $self->{maxnum} = $max_num;
    $self->{filename} = $filename;

    # Make a deep copy, allowing {contents} to be an independent work array
    foreach my $i (1..$max_num) {
        if ($tmp_contents[$i]) {
            $self->{loaded_contents}->[$i] =
                [ map { OpenSSL::Ordinals::Item->new($_) }
                  @{$tmp_contents[$i]} ];
        }
    }
    $self->{loaded_maxnum} = $max_num;
    return 1;
}

=item B<$ordinals-E<gt>rewrite>

If an ordinals file has been loaded, it gets rewritten with the data from
the current work database.

=cut

sub rewrite {
    my $self = shift;

    $self->write($self->{filename});
}

=item B<$ordinals-E<gt>write FILENAME>

Writes the current work database data to the ordinals file FILENAME.
This also validates the data, see B<$ordinals-E<gt>validate> below.

=cut

sub write {
    my $self = shift;
    my $filename = shift;

    croak "Undefined filename" unless defined($filename);

    $self->validate();

    open F, '>', $filename or croak "Unable to open $filename";
    foreach ($self->items(by => by_number())) {
        print F $_->to_string(),"\n";
    }
    close F;
    $self->{filename} = $filename;
    $self->{loaded_maxnum} = $self->{maxnum};
    return 1;
}

=item B<$ordinals-E<gt>items> I<%options>

Returns a list of items according to a set of criteria.  The criteria is
given in form keyed pair form, i.e. a series of C<key =E<gt> value> pairs.
Available options are:

=over 4

=item B<sort =E<gt> SORTFUNCTION>

SORTFUNCTION is a reference to a function that takes two arguments, which
correspond to the classic C<$a> and C<$b> that are available in a C<sort>
block.

=item B<filter =E<gt> FILTERFUNCTION>

FILTERFUNTION is a reference to a function that takes one argument, which
is every OpenSSL::Ordinals::Item element available.

=back

=cut

sub items {
    my $self = shift;
    my %opts = @_;

    my $comparator = $opts{sort};
    my $filter = $opts{filter} // sub { 1; };

    my @l = undef;
    if (ref($filter) eq 'ARRAY') {
        # run a "magic" filter
        if    ($filter->[0] == F_NUMBER) {
            my $index = $filter->[1];
            @l = $index ? @{$self->{contents}->[$index] // []} : ();
        } elsif ($filter->[0] == F_NAME) {
            my $index = $self->{name2num}->{$filter->[1]};
            @l = $index ? @{$self->{contents}->[$index] // []} : ();
        } else {
            croak __PACKAGE__."->items called with invalid filter";
        }
    } elsif (ref($filter) eq 'CODE') {
        @l = grep { $filter->($_) }
            map { @{$_ // []} }
            @{$self->{contents}};
    } else {
        croak __PACKAGE__."->items called with invalid filter";
    }

    return sort { $comparator->($a, $b); } @l
        if (defined $comparator);
    return @l;
}

# Put an array of items back into the object after having checked consistency
# If there are exactly two items:
# - They MUST have the same number
# - For platforms, both MUST hold the same ones, but with opposite values
# - For features, both MUST hold the same ones.
# If there's just one item, just put it in the slot of its number
# In all other cases, something is wrong
sub _putback {
    my $self = shift;
    my @items = @_;

    if (scalar @items < 1 || scalar @items > 2) {
        croak "Wrong number of items: ", scalar @items, " : ",
            join(", ", map { $_->name() } @items), "\n";
    }
    if (scalar @items == 2) {
        # Collect some data
        my %numbers = ();
        my %versions = ();
        my %features = ();
        foreach (@items) {
            $numbers{$_->number()} = 1;
            $versions{$_->version()} = 1;
            foreach ($_->features()) {
                $features{$_}++;
            }
        }

        # Check that all items we're trying to put back have the same number
        croak "Items don't have the same numeral: ",
            join(", ", map { $_->name()." => ".$_->number() } @items), "\n"
            if (scalar keys %numbers > 1);
        croak "Items don't have the same version: ",
            join(", ", map { $_->name()." => ".$_->version() } @items), "\n"
            if (scalar keys %versions > 1);

        # Check that both items run with the same features
        foreach (@items) {
        }
        foreach (keys %features) {
            delete $features{$_} if $features{$_} == 2;
        }
        croak "Features not in common between ",
            $items[0]->name(), " and ", $items[1]->name(), ":",
            join(", ", sort keys %features), "\n"
            if %features;

        # Check that all platforms exist in both items, and have opposite values
        my @platforms = ( { $items[0]->platforms() },
                          { $items[1]->platforms() } );
        foreach my $platform (keys %{$platforms[0]}) {
            if (exists $platforms[1]->{$platform}) {
                if ($platforms[0]->{$platform} != !$platforms[1]->{$platform}) {
                    croak "Platforms aren't opposite: ",
                        join(", ",
                             map { my %tmp_h = $_->platforms();
                                   $_->name().":".$platform
                                       ." => "
                                       .$tmp_h{$platform} } @items),
                        "\n";
                }

                # We're done with these
                delete $platforms[0]->{$platform};
                delete $platforms[1]->{$platform};
            }
        }
        # If there are any remaining platforms, something's wrong
        if (%{$platforms[0]} || %{$platforms[0]}) {
            croak "There are platforms not in common between ",
                $items[0]->name(), " and ", $items[1]->name(), "\n";
        }
    }
    $self->{contents}->[$items[0]->number()] = [ @items ];
}

sub _parse_platforms {
    my $self = shift;
    my @defs = @_;

    my %platforms = ();
    foreach (@defs) {
        m{^(!)?};
        my $op = !(defined $1 && $1 eq '!');
        my $def = $';

        if ($def =~ m{^_?WIN32$})                   { $platforms{$&} = $op; }
        if ($def =~ m{^__FreeBSD__$})               { $platforms{$&} = $op; }
# For future support
#       if ($def =~ m{^__DragonFly__$})             { $platforms{$&} = $op; }
#       if ($def =~ m{^__OpenBSD__$})               { $platforms{$&} = $op; }
#       if ($def =~ m{^__NetBSD__$})                { $platforms{$&} = $op; }
        if ($def =~
            m{^OPENSSL_(EXPORT_VAR_AS_FUNCTION)$})  { $platforms{$1} = $op; }
        if ($def =~ m{^OPENSSL_SYS_})               { $platforms{$'} = $op; }
    }

    return %platforms;
}

sub _parse_features {
    my $self = shift;
    my @defs = @_;

    my %features = ();
    foreach (@defs) {
        m{^(!)?};
        my $op = !(defined $1 && $1 eq '!');
        my $def = $';

        if ($def =~ m{^ZLIB$})                      { $features{$&} =  $op; }
        if ($def =~ m{^OPENSSL_USE_})               { $features{$'} =  $op; }
        if ($def =~ m{^OPENSSL_NO_})                { $features{$'} = !$op; }
        if ($def =~ m{^DEPRECATEDIN_(.*)$})         { $features{$&} = !$op; }
    }

    return %features;
}

=item B<$ordinals-E<gt>add NAME, TYPE, LIST>

Adds a new item named NAME with the type TYPE, and a set of C macros in
LIST that are expected to be defined or undefined to use this symbol, if
any.  For undefined macros, they each must be prefixed with a C<!>.

If this symbol already exists in loaded data, it will be rewritten using
the new input data, but will keep the same ordinal number and version.
If it's entirely new, it will get a new number and the current default
version.  The new ordinal number is a simple increment from the last
maximum number.

=cut

sub add {
    my $self = shift;
    my $name = shift;
    my $type = shift;           # FUNCTION or VARIABLE
    my @defs = @_;              # Macros from #ifdef and #ifndef
                                # (the latter prefixed with a '!')

    # call signature for debug output
    my $verbsig = "add('$name' , '$type' , [ " . join(', ', @defs) . " ])";

    croak __PACKAGE__."->add got a bad type '$type'"
        unless $type eq 'FUNCTION' || $type eq 'VARIABLE';

    my %platforms = _parse_platforms(@defs);
    my %features = _parse_features(@defs);

    my @items = $self->items(filter => f_name($name));
    my $version = @items ? $items[0]->version() : $self->{currversion};
    my $number = @items ? $items[0]->number() : ++$self->{maxnum};
    print STDERR "DEBUG[",__PACKAGE__,":add] $verbsig\n",
        @items ? map { "\t".$_->to_string()."\n" } @items : "No previous items\n",
        if $self->{debug};
    @items = grep { $_->exists() } @items;

    my $new_item =
        OpenSSL::Ordinals::Item->new( name          => $name,
                                      type          => $type,
                                      number        => $number,
                                      version       => $version,
                                      exists        => 1,
                                      platforms     => { %platforms },
                                      features      => [
                                          grep { $features{$_} } keys %features
                                      ] );

    push @items, $new_item;
    print STDERR "DEBUG[",__PACKAGE__,"::add] $verbsig\n", map { "\t".$_->to_string()."\n" } @items
        if $self->{debug};
    $self->_putback(@items);

    # If an alias was defined beforehand, add an item for it now
    my $alias = $self->{aliases}->{$name};
    delete $self->{aliases}->{$name};

    # For the caller to show
    my @returns = ( $new_item );
    push @returns, $self->add_alias($alias->{name}, $name, @{$alias->{defs}})
        if defined $alias;
    return @returns;
}

=item B<$ordinals-E<gt>add_alias ALIAS, NAME, LIST>

Adds an alias ALIAS for the symbol NAME, and a set of C macros in LIST
that are expected to be defined or undefined to use this symbol, if any.
For undefined macros, they each must be prefixed with a C<!>.

If this symbol already exists in loaded data, it will be rewritten using
the new input data.  Otherwise, the data will just be store away, to wait
that the symbol NAME shows up.

=cut

sub add_alias {
    my $self = shift;
    my $alias = shift;          # This is the alias being added
    my $name  = shift;          # For this name (assuming it exists)
    my @defs = @_;              # Platform attributes for the alias

    # call signature for debug output
    my $verbsig =
        "add_alias('$alias' , '$name' , [ " . join(', ', @defs) . " ])";

    croak "You're kidding me..." if $alias eq $name;

    my %platforms = _parse_platforms(@defs);
    my %features = _parse_features(@defs);

    croak "Alias with associated features is forbidden\n"
        if %features;

    my $f_byalias = f_name($alias);
    my $f_byname = f_name($name);
    my @items = $self->items(filter => $f_byalias);
    foreach my $item ($self->items(filter => $f_byname)) {
        push @items, $item unless grep { $_ == $item } @items;
    }
    @items = grep { $_->exists() } @items;

    croak "Alias already exists ($alias => $name)"
        if scalar @items > 1;
    if (scalar @items == 0) {
        # The item we want to alias for doesn't exist yet, so we cache the
        # alias and hope the item we're making an alias of shows up later
        $self->{aliases}->{$name} = { name => $alias, defs => [ @defs ] };

        print STDERR "DEBUG[",__PACKAGE__,":add_alias] $verbsig\n",
            "\tSet future alias $alias => $name\n"
            if $self->{debug};
        return ();
    } elsif (scalar @items == 1) {
        # The rule is that an alias is more or less a copy of the original
        # item, just with another name.  Also, the platforms given here are
        # given to the original item as well, with opposite values.
        my %alias_platforms = $items[0]->platforms();
        foreach (keys %platforms) {
            $alias_platforms{$_} = !$platforms{$_};
        }
        # We supposedly do now know how to do this...  *ahem*
        $items[0]->{platforms} = { %alias_platforms };

        my $alias_item = OpenSSL::Ordinals::Item->new(
            name          => $alias,
            type          => $items[0]->type(),
            number        => $items[0]->number(),
            version       => $items[0]->version(),
            exists        => $items[0]->exists(),
            platforms     => { %platforms },
            features      => [ $items[0]->features() ]
           );
        push @items, $alias_item;

        print STDERR "DEBUG[",__PACKAGE__,":add_alias] $verbsig\n",
            map { "\t".$_->to_string()."\n" } @items
            if $self->{debug};
        $self->_putback(@items);

        # For the caller to show
        return ( $alias_item->to_string() );
    }
    croak "$name has an alias already (trying to add alias $alias)\n",
        "\t", join(", ", map { $_->name() } @items), "\n";
}

=item B<$ordinals-E<gt>set_version VERSION>

Sets the default version for new symbol to VERSION.

=cut

sub set_version {
    my $self = shift;
    my $version = shift;

    $version //= '*';
    $version =~ s|-.*||g;
    $version =~ s|\.|_|g;
    $self->{currversion} = $version;
    foreach ($self->items(filter => sub { $_[0] eq '*' })) {
        $_->{version} = $self->{currversion};
    }
    return 1;
}

=item B<$ordinals-E<gt>invalidate>

Invalidates the whole working database.  The practical effect is that all
symbols are set to not exist, but are kept around in the database to retain
ordinal numbers and versions.

=cut

sub invalidate {
    my $self = shift;

    foreach (@{$self->{contents}}) {
        foreach (@{$_ // []}) {
            $_->{exists} = 0;
        }
    }
    $self->{stats} = {};
}

=item B<$ordinals-E<gt>validate>

Validates the current working database by collection statistics on how many
symbols were added and how many were changed.  These numbers can be retrieved
with B<$ordinals-E<gt>stats>.

=cut

sub validate {
    my $self = shift;

    $self->{stats} = {};
    for my $i (1..$self->{maxnum}) {
        if ($i > $self->{loaded_maxnum}
                || (!@{$self->{loaded_contents}->[$i] // []}
                    && @{$self->{contents}->[$i] // []})) {
            $self->{stats}->{new}++;
        }
        next if ($i > $self->{loaded_maxnum});

        my @loaded_strings =
            map { $_->to_string() } @{$self->{loaded_contents}->[$i] // []};
        my @current_strings =
            map { $_->to_string() } @{$self->{contents}->[$i] // []};

        foreach my $str (@current_strings) {
            @loaded_strings = grep { $str ne $_ } @loaded_strings;
        }
        if (@loaded_strings) {
            $self->{stats}->{modified}++;
        }
    }
}

=item B<$ordinals-E<gt>stats>

Returns the statistics that B<validate> calculate.

=cut

sub stats {
    my $self = shift;

    return %{$self->{stats}};
}

=back

=head2 Data elements

Data elements, which is each line in an ordinals file, are instances
of a separate class, OpenSSL::Ordinals::Item, with its own methods:

=over 4

=cut

package OpenSSL::Ordinals::Item;

use strict;
use warnings;
use Carp;

=item B<new> I<%options>

Creates a new instance of the C<OpenSSL::Ordinals::Item> class.  It takes
options in keyed pair form, i.e. a series of C<key =E<gt> value> pairs.
Available options are:

=over 4

=item B<from =E<gt> STRING>

This will create a new item, filled with data coming from STRING.

STRING must conform to the following EBNF description:

  ordinal string = symbol, spaces, ordinal, spaces, version, spaces,
                   exist, ":", platforms, ":", type, ":", features;
  spaces         = space, { space };
  space          = " " | "\t";
  symbol         = ( letter | "_"), { letter | digit | "_" };
  ordinal        = number;
  version        = number, "_", number, "_", number, letter, [ letter ];
  exist          = "EXIST" | "NOEXIST";
  platforms      = platform, { ",", platform };
  platform       = ( letter | "_" ) { letter | digit | "_" };
  type           = "FUNCTION" | "VARIABLE";
  features       = feature, { ",", feature };
  feature        = ( letter | "_" ) { letter | digit | "_" };
  number         = digit, { digit };

(C<letter> and C<digit> are assumed self evident)

=item B<name =E<gt> STRING>, B<number =E<gt> NUMBER>, B<version =E<gt> STRING>,
      B<exists =E<gt> BOOLEAN>, B<type =E<gt> STRING>,
      B<platforms =E<gt> HASHref>, B<features =E<gt> LISTref>

This will create a new item with data coming from the arguments.

=back

=cut

sub new {
    my $class = shift;

    if (ref($_[0]) eq $class) {
        return $class->new( map { $_ => $_[0]->{$_} } keys %{$_[0]} );
    }

    my %opts = @_;

    croak "No argument given" unless %opts;

    my $instance = undef;
    if ($opts{from}) {
        my @a = split /\s+/, $opts{from};

        croak "Badly formatted ordinals string: $opts{from}"
            unless ( scalar @a == 4
                     && $a[0] =~ /^[A-Za-z_][A-Za-z_0-9]*$/
                     && $a[1] =~ /^\d+$/
                     && $a[2] =~ /^(?:\*|\d+_\d+_\d+(?:[a-z]{0,2}))$/
                     && $a[3] =~ /^
                                  (?:NO)?EXIST:
                                  [^:]*:
                                  (?:FUNCTION|VARIABLE):
                                  [^:]*
                                  $
                                 /x );

        my @b = split /:/, $a[3];
        %opts = ( name          => $a[0],
                  number        => $a[1],
                  version       => $a[2],
                  exists        => $b[0] eq 'EXIST',
                  platforms     => { map { m|^(!)?|; $' => !$1 }
                                         split /,/,$b[1] },
                  type          => $b[2],
                  features      => [ split /,/,$b[3] // '' ] );
    }

    if ($opts{name} && $opts{version} && defined $opts{exists} && $opts{type}
            && ref($opts{platforms} // {}) eq 'HASH'
            && ref($opts{features} // []) eq 'ARRAY') {
        $instance = { name      => $opts{name},
                      type      => $opts{type},
                      number    => $opts{number},
                      version   => $opts{version},
                      exists    => !!$opts{exists},
                      platforms => { %{$opts{platforms} // {}} },
                      features  => [ sort @{$opts{features} // []} ] };
    } else {
        croak __PACKAGE__."->new() called with bad arguments\n".
            join("", map { "    $_\t=> ".$opts{$_}."\n" } sort keys %opts);
    }

    return bless $instance, $class;
}

sub DESTROY {
}

=item B<$item-E<gt>name>

The symbol name for this item.

=item B<$item-E<gt>number>

The positional number for this item.

=item B<$item-E<gt>version>

The version number for this item.  Please note that these version numbers
have underscore (C<_>) as a separator the the version parts.

=item B<$item-E<gt>exists>

A boolean that tells if this symbol exists in code or not.

=item B<$item-E<gt>platforms>

A hash table reference.  The keys of the hash table are the names of
the specified platforms, with a value of 0 to indicate that this symbol
isn't available on that platform, and 1 to indicate that it is.  Platforms
that aren't mentioned default to 1.

=item B<$item-E<gt>type>

C<FUNCTION> or C<VARIABLE>, depending on what the symbol represents.
Some platforms do not care about this, others do.

=item B<$item-E<gt>features>

An array reference, where every item indicates a feature where this symbol
is available.  If no features are mentioned, the symbol is always available.
If any feature is mentioned, this symbol is I<only> available when those
features are enabled.

=cut

our $AUTOLOAD;

# Generic getter
sub AUTOLOAD {
    my $self = shift;
    my $funcname = $AUTOLOAD;
    (my $item = $funcname) =~ s|.*::||g;

    croak "$funcname called as setter" if @_;
    croak "$funcname invalid" unless exists $self->{$item};
    return $self->{$item} if ref($self->{$item}) eq '';
    return @{$self->{$item}} if ref($self->{$item}) eq 'ARRAY';
    return %{$self->{$item}} if ref($self->{$item}) eq 'HASH';
}

=item B<$item-E<gt>to_string>

Converts the item to a string that can be saved in an ordinals file.

=cut

sub to_string {
    my $self = shift;

    croak "Too many arguments" if @_;
    my %platforms = $self->platforms();
    my @features = $self->features();
    return sprintf "%-39s %d\t%s\t%s:%s:%s:%s",
        $self->name(),
        $self->number(),
        $self->version(),
        $self->exists() ? 'EXIST' : 'NOEXIST',
        join(',', (map { ($platforms{$_} ? '' : '!') . $_ }
                   sort keys %platforms)),
        $self->type(),
        join(',', @features);
}

=back

=head2 Comparators and filters

For the B<$ordinals-E<gt>items> method, there are a few functions to create
comparators based on specific data:

=over 4

=cut

# Go back to the main package to create comparators and filters
package OpenSSL::Ordinals;

# Comparators...

=item B<by_name>

Returns a comparator that will compare the names of two OpenSSL::Ordinals::Item
objects.

=cut

sub by_name {
    return sub { $_[0]->name() cmp $_[1]->name() };
}

=item B<by_number>

Returns a comparator that will compare the ordinal numbers of two
OpenSSL::Ordinals::Item objects.

=cut

sub by_number {
    return sub { $_[0]->number() <=> $_[1]->number() };
}

=item B<by_version>

Returns a comparator that will compare the version of two
OpenSSL::Ordinals::Item objects.

=cut

sub by_version {
    sub _ossl_versionsplit {
        my $textversion = shift;
        return $textversion if $textversion eq '*';
        my ($major,$minor,$edit,$patch) =
            $textversion =~ /^(\d+)_(\d+)_(\d+)([a-z]{0,2})$/;
        return ($major,$minor,$edit,$patch);
    }

    return sub {
        my @a_split = _ossl_versionsplit($_[0]->version());
        my @b_split = _ossl_versionsplit($_[1]->version());
        my $verdict = 0;
        while (@a_split) {
            # The last part is a letter sequence (or a '*')
            if (scalar @a_split == 1) {
                $verdict = $a_split[0] cmp $b_split[0];
            } else {
                $verdict = $a_split[0] <=> $b_split[0];
            }
            shift @a_split;
            shift @b_split;
            last unless $verdict == 0;
        }
        $verdict;
    };
}

=back

There are also the following filters:

=over 4

=cut

# Filters...  these are called by grep, the return sub must use $_ for
# the item to check

=item B<f_version VERSION>

Returns a filter that only lets through symbols with a version number
matching B<VERSION>.

=cut

sub f_version {
    my $version = shift;

    $version =~ s|\.|_|g if $version;
    croak "No version specified"
        unless $version && $version =~ /^\d_\d_\d[a-z]{0,2}$/;

    return sub { $_[0]->version() eq $version };
}

=item B<f_number NUMBER>

Returns a filter that only lets through symbols with the ordinal number
matching B<NUMBER>.

NOTE that this returns a "magic" value that can not be used as a function.
It's only useful when passed directly as a filter to B<items>.

=cut

sub f_number {
    my $number = shift;

    croak "No number specified"
        unless $number && $number =~ /^\d+$/;

    return [ F_NUMBER, $number ];
}


=item B<f_name NAME>

Returns a filter that only lets through symbols with the symbol name
matching B<NAME>.

NOTE that this returns a "magic" value that can not be used as a function.
It's only useful when passed directly as a filter to B<items>.

=cut

sub f_name {
    my $name = shift;

    croak "No name specified"
        unless $name;

    return [ F_NAME, $name ];
}

=back

=head1 AUTHORS

Richard Levitte E<lt>levitte@openssl.orgE<gt>.

=cut

1;
