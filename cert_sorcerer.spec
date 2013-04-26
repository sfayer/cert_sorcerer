# Remove python byte-code compile step
%global __os_install_post %(echo '%{__os_install_post}' | sed -e 's!/usr/lib[^[:space:]]*/brp-python-bytecompile[[:space:]].*$!!g')

Name:           cert_sorcerer
Version:        1.0.0
Release:        1%{?dist}
Summary:        A tool for requesting certificates
Group:          Applications/Internet
License:        GPLv3
URL:            https://github.com/sfayer/cert_sorcerer
Source0:        https://raw.github.com/sfayer/cert_sorcerer/master/CS.py
Source1:        https://raw.github.com/sfayer/cert_sorcerer/master/README
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
* Fri Apr 26 2013 Simon Fayer <sf105@ic.ac.uk>
- Initial version.

