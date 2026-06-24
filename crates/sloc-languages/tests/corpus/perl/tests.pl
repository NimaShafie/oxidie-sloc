use strict;
use warnings;
use Test::More;

subtest 'arithmetic' => sub {
    ok(1 + 1 == 2, 'addition works');
    is(2 * 3, 6, 'multiplication works');
    is_deeply([1, 2], [1, 2], 'lists match');
};

done_testing();
