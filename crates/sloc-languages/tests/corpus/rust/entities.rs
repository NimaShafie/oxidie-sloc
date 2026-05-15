use std::io;
use std::fmt;

pub struct Point {
    x: f64,
    y: f64,
}

pub enum Color {
    Red,
    Green,
    Blue,
}

pub trait Shape {
    fn area(&self) -> f64;
}

impl Point {
    pub fn new(x: f64, y: f64) -> Self {
        let pt = Point { x, y };
        pt
    }

    pub fn distance(&self) -> f64 {
        let sq = self.x * self.x + self.y * self.y;
        sq.sqrt()
    }
}

pub fn helper() {
    let _tmp = 42;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let p = Point::new(3.0, 4.0);
        assert_eq!(p.distance(), 5.0);
    }

    #[test]
    fn test_color() {
        let c = Color::Red;
        assert!(matches!(c, Color::Red));
    }
}
