# Homebrew formula for oxide-sloc
#
# To use with a private tap:
#   brew tap oxide-sloc/oxide-sloc https://github.com/oxide-sloc/homebrew-oxide-sloc
#   brew install oxide-sloc/oxide-sloc/oxide-sloc
#
# To build from source (requires Rust installed):
#   brew install --build-from-source oxide-sloc
#
# The sha256 checksum below must be updated on each release.
# Run: curl -L <url> | sha256sum

class OxideSloc < Formula
  desc "IEEE 1045-1992 SLOC analysis, test detection, and code metrics workbench"
  homepage "https://github.com/oxide-sloc/oxide-sloc"
  url "https://github.com/oxide-sloc/oxide-sloc/archive/refs/tags/v1.6.1.tar.gz"
  sha256 "3a01158786e19a5ed452643f95b4918852f54a04219c008ed121c2ac4e791cb8"
  license "AGPL-3.0-or-later"
  head "https://github.com/oxide-sloc/oxide-sloc.git", branch: "main"

  depends_on "rust" => :build

  def install
    system "cargo", "install", *std_cargo_args(path: "crates/sloc-cli")
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/oxide-sloc --version")
    (testpath/"hello.rs").write "fn main() { println!(\"hello\"); }\n"
    output = shell_output("#{bin}/oxide-sloc analyze #{testpath} --plain")
    assert_match "Rust", output
  end
end
