open OUnit2

let test_add _ =
  assert_equal 4 (2 + 2)

let test_bool _ =
  assert_bool "true holds" true

let suite =
  "math" >::: [ "add" >:: test_add; "bool" >:: test_bool ]
