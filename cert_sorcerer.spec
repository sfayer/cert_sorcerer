# Remove python byte-code compile step
%global __os_install_post %(echo '%{__os_install_post}' | sed -e 's!/usr/lib[^[:space:]]*/brp-python-bytecompile[[:space:]].*$!!g')

Name:           cert_sorcerer
Version:        1.0.10
Release:        1%{?dist}
Summary:        A tool for requesting certificates
Group:          Applications/Internet
License:        GPLv3
URL:            https://github.com/sfayer/cert_sorcerer
Source0:        https://raw.github.com/sfayer/cert_sorcerer/v1_0_10/CS.py30
Source1:        https://raw.github.com/sfayer/cert_sorcerer/v1_0_10/CS.py27
Source2:        https://raw.github.com/sfayer/cert_sorcerer/v1_0_10/README
Source3:        https://raw.github.com/sfayer/cert_sorcerer/v1_0_10/NOTES
Source4:        https://raw.github.com/sfayer/cert_sorcerer/v1_0_10/QUICKSTART
Source5:        https://raw.github.com/sfayer/cert_sorcerer/v1_0_10/COPYING
BuildArch:      noarch
BuildRoot:      %(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)
%if 0%{?rhel} >= 8
Requires:       openssl python3 python3-pycurl python3-pyOpenSSL
%else
Requires:       openssl python python-pycurl pyOpenSSL
%endif

%description
Cert Sorcerer is a tool for requestion certificates from a CA web-service.
You should customise this package with your various local parameters.

%prep
cp %{SOURCE2} README
cp %{SOURCE3} NOTES
cp %{SOURCE4} QUICKSTART
cp %{SOURCE5} COPYING

%build

%install
rm -Rf %{buildroot}
# Install binary
mkdir -p %{buildroot}%{_bindir}
%if 0%{?rhel} >= 8
cp %{SOURCE0} %{buildroot}%{_bindir}/CS.py
%else
cp %{SOURCE1} %{buildroot}%{_bindir}/CS.py
%endif
chmod 755 %{buildroot}%{_bindir}/CS.py

%clean
rm -rf %{buildroot}


%files
%defattr(-,root,root,-)
%{_bindir}/CS.py
%doc README NOTES QUICKSTART COPYING

%changelog
* Wed Aug 18 2021 Simon Fayer <sf105@ic.ac.uk> - 1.0.10-1
- Use sha256 for CSR signatures.

* Wed Feb 03 2021 Simon Fayer <sf105@ic.ac.uk> - 1.0.9-1
- Use new post interface for fetching certs due to '//' URL problem.

* Fri May 01 2020 Simon Fayer <sf105@ic.ac.uk> - 1.0.8-1
- Add support for python3 (CentOS8).

* Wed May 16 2018 Simon Fayer <sf105@ic.ac.uk> - 1.0.7-1
- Add support for extra SAN values in certificates.

* Fri Jun 28 2013 Simon Fayer <sf105@ic.ac.uk> - 1.0.6-1
- Support for DNs containing "/".
- Print full DN before prompting the user.
- Fixed typo in p12 instructions (chown -> chmod).
- Change user agent to reflect actual name & version.

* Thu Jun 27 2013 Simon Fayer <sf105@ic.ac.uk> - 1.0.5-1
- Improve error message if usercert is missing.

* Sat Jun 15 2013 Simon Fayer <sf105@ic.ac.uk> - 1.0.4-1
- Minor updates to the code style and documentation.

* Tue May 07 2013 Simon Fayer <sf105@ic.ac.uk> - 1.0.3-1
- Use slightly modified interface to fetch certs.
- New --fetch option to make fetching certs safer in batch mode.

* Wed May 01 2013 Simon Fayer <sf105@ic.ac.uk> - 1.0.2-1
- Ensure private key is kept in PKCS#1 format.
- Other minor fixes.

* Wed May 01 2013 Simon Fayer <sf105@ic.ac.uk> - 1.0.1-1
- Latest version.
- New batch mode.

* Fri Apr 26 2013 Simon Fayer <sf105@ic.ac.uk> - 1.0.0-1
- Initial version.

