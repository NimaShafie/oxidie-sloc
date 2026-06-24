#!/usr/bin/env bats

@test "addition works" {
  result=$((2 + 2))
  [ "$result" -eq 4 ]
}

@test "subtraction works" {
  result=$((5 - 3))
  [ "$result" -eq 2 ]
}
