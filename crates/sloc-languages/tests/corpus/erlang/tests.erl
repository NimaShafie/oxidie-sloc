-module(math_tests).
-include_lib("eunit/include/eunit.hrl").

add_test() ->
    ?assertEqual(4, 2 + 2).

sub_test() ->
    ?assert(3 - 1 =:= 2).
