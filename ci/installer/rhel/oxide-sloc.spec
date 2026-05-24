Name:           oxide-sloc
Version:        %{_version}
Release:        1%{?dist}
Summary:        Code metrics workbench — SLOC analysis and unit test detection
License:        AGPL-3.0-or-later
URL:            https://github.com/oxide-sloc/oxide-sloc
BuildArch:      x86_64

# Source0 is a pre-built static binary placed in ~/rpmbuild/SOURCES/ by make-rpm.sh.
# No compilation happens on the target machine — safe for EDR-protected RHEL 8/9.
Source0:        oxide-sloc

%description
oxide-sloc is a Rust-based code metrics workbench that provides SLOC analysis,
unit test detection, and HTML/PDF coverage reports via a CLI and a localhost
web UI (http://127.0.0.1:4317 by default).

The binary is fully static (musl) with no runtime library dependencies.
Run "oxide-sloc serve" from any project directory; reports are stored in out/.

%prep
# Nothing to prepare — binary-only package.

%build
# Nothing to build — binary-only package.

%install
install -Dm755 %{SOURCE0} %{buildroot}/usr/local/bin/oxide-sloc

%files
/usr/local/bin/oxide-sloc

%changelog
* Mon May 18 2026 Nima Shafie <nimzshafie@gmail.com> - %{_version}-1
- See https://github.com/oxide-sloc/oxide-sloc/releases for full changelog.
