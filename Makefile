IS_SANDBOX=$(shell perl -e 'print "yes" if -e q{/var/cpanel/dev_sandbox}')
PKG=$(shell pwd)/pkg

all:
	@echo 'This Makefile is only used during the build process.'
	@echo 'Please update to cPanel & WHM 11.40 or use the pkg/install script.'

define build_rules
	@[ $(IS_SANDBOX) = yes ] || exit 1
	rm -fr $(1)/Cpanel/Security/Advisor.pm $(1)/Cpanel/Security/Advisor $(1)/whostmgr/templates/securityadvisor
	mkdir -p $(1)/Cpanel/Security/Advisor/Assessors $(1)/whostmgr/docroot/templates/securityadvisor
	for i in $(PKG)/Cpanel/Security/Advisor.pm \
			$(PKG)/Cpanel/Security/Advisor/Assessors.pm $(PKG)/Cpanel/Security/Advisor/Assessors/*.pm; do \
		stripped=`echo $$i | sed -e 's,^$(PKG),,'`; \
		rm -fr $(1)/$$stripped; $(2) $$i $(1)/$$stripped; \
		done
	for i in $(PKG)/templates/*.tmpl; do \
		stripped=`basename $$i`; \
		cp -f $$i $(1)/whostmgr/docroot/templates/securityadvisor/$$stripped; \
		perl -i -pe 's{/addon_plugins/}{}g'	$(1)/whostmgr/docroot/templates/securityadvisor/$$stripped; \
	done
	$(2) $(PKG)/icon/ico-security-advisor.png $(1)/whostmgr/docroot/themes/x/icons/
	mkdir -m 700 -p $(1)/whostmgr/docroot/cgi/securityadvisor
	$(2) $(PKG)/cgi/addon_securityadvisor.cgi $(1)/whostmgr/docroot/cgi/securityadvisor/index.cgi
endef

sandbox:
	$(call build_rules,/usr/local/cpanel,ln -sf)

publish:
	[ -n "$(DESTDIR)" ] || exit 1
	$(call build_rules,$(DESTDIR)/cpanel,cp -f)
