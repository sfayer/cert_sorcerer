# Remove python byte-code compile step
%global __os_install_post %(echo '%{__os_install_post}' | sed -e 's!/usr/lib[^[:space:]]*/brp-python-bytecompile[[:space:]].*$!!g')

Name:           cert_sorcerer
Version:        1.0.6
Release:        1%{?dist}
Summary:        A tool for requesting certificates
Group:          Applications/Internet
License:        GPLv3
URL:            https://github.com/sfayer/cert_sorcerer
Source0:        https://raw.github.com/sfayer/cert_sorcerer/v1_0_6/CS.py
Source1:        https://raw.github.com/sfayer/cert_sorcerer/v1_0_6/README
BuildArch:      noarch
BuildRoot:      %(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)
Requires:       openssl python python-pycurl pyOpenSSL

%description
Cert Sorcerer is a tool for requestion certificates from a CA web-service.
You should customise this package with your various local parameters.

%prep
cp %{SOURCE1} README

%build

%install
rm -Rf $RPM_BUILD_ROOT
# Install binary
mkdir -p %{buildroot}%{_bindir}
cp %{SOURCE0} %{buildroot}%{_bindir}/CS.py
chmod 755 %{buildroot}%{_bindir}/CS.py

%clean
rm -rf %{buildroot}


%files
%defattr(-,root,root,-)
%{_bindir}/CS.py*
%doc README

%changelog
* Fri Jun 28 2013 Simon Fayer <sf105@ic.ac.uk> - 1.0.6-1
- Nothing yet.

* Thu Jun 27 2013 Simon Fayer <sf105@ic.ac.uk> - 1.0.5-1
- Improve error message if usercert is missing.

* Sat Jun 15 2013 Simon Fayer <sf105@ic.ac.uk> - 1.0.4-1
- Minor updates to the code style and documentation.

* Wed May 07 2013 Simon Fayer <sf105@ic.ac.uk> - 1.0.3-1
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

