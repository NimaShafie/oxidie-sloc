package main

import "fmt"

type Point struct {
	X float64
	Y float64
}

func (p Point) Area() float64 {
	var result float64
	result = p.X * p.Y
	return result
}

func helper() {
	var x int = 5
	fmt.Println(x)
}

func TestPoint(t interface{}) {
	_ = t
}

func BenchmarkHelper(b interface{}) {
	helper()
	_ = b
}
