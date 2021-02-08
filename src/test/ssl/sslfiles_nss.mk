#-------------------------------------------------------------------------
#
# Makefile for sslfiles using NSS
#
#   The SSL test files are completely disjoint from the rest of the build; they
#   don't rely on other targets or on Makefile.global.  The targets in this
#   file rely on the certificates and keys generated by the OpenSSL backend
#   support.
#
# Portions Copyright (c) 1996-2021, PostgreSQL Global Development Group
# Portions Copyright (c) 1994, Regents of the University of California
#
# src/test/ssl/sslfiles_nss.mk
#
#-------------------------------------------------------------------------

# Even though we in practice could get away with far fewer NSS databases, they
# are generated to mimic the setup for the OpenSSL tests in order to ensure
# we isolate the same behavior between the backends. The database name should
# contain the files included for easier test suite code reading.
NSSFILES := ssl/nss/client_ca.crt.db \
	ssl/nss/server_ca.crt.db \
	ssl/nss/root+server_ca.crt.db \
	ssl/nss/root+client_ca.crt.db \
	ssl/nss/client.crt__client.key.db \
	ssl/nss/client-revoked.crt__client-revoked.key.db \
	ssl/nss/server-cn-only.crt__server-password.key.db \
	ssl/nss/server-cn-only.crt__server-cn-only.key.db \
	ssl/nss/server-cn-only.crt__server-cn-only.key.crldir.db \
	ssl/nss/root.crl \
	ssl/nss/server.crl \
	ssl/nss/client.crl \
	ssl/nss/server-multiple-alt-names.crt__server-multiple-alt-names.key.db \
	ssl/nss/server-single-alt-name.crt__server-single-alt-name.key.db \
	ssl/nss/server-cn-and-alt-names.crt__server-cn-and-alt-names.key.db \
	ssl/nss/server-no-names.crt__server-no-names.key.db \
	ssl/nss/server-revoked.crt__server-revoked.key.db \
	ssl/nss/root+client.crl \
	ssl/nss/client+client_ca.crt__client.key.db \
	ssl/nss/client.crt__client-encrypted-pem.key.db \
	ssl/nss/root+server_ca.crt__server.crl.db \
	ssl/nss/root+server_ca.crt__root+server.crl.db \
	ssl/nss/root+server_ca.crt__root+server.crldir.db \
	ssl/nss/native_ca-root.db \
	ssl/nss/native_server-root.db \
	ssl/nss/native_client-root.db \
	ssl/nss/client_ext.crt__client_ext.key.db

nssfiles: $(NSSFILES)

ssl/nss/%_ca.crt.db: ssl/%_ca.crt
	$(MKDIR_P) $@
	certutil -d "sql:$@" -N --empty-password
	certutil -d "sql:$@" -A -n $*_ca.crt -i ssl/$*_ca.crt -t "CT,C,C"

ssl/nss/root+server_ca.crt__server.crl.db: ssl/root+server_ca.crt ssl/nss/server.crl
	$(MKDIR_P) $@
	certutil -d "sql:$@" -N --empty-password
	certutil -d "sql:$@" -A -n ssl/root+server_ca.crt -i ssl/root+server_ca.crt -t "CT,C,C"
	crlutil -I -i ssl/nss/server.crl -d $@ -B

ssl/nss/root+server_ca.crt__root+server.crl.db: ssl/root+server_ca.crt ssl/nss/root.crl ssl/nss/server.crl
	$(MKDIR_P) $@
	certutil -d "sql:$@" -N --empty-password
	certutil -d "sql:$@" -A -n ssl/root+server_ca.crt -i ssl/root+server_ca.crt -t "CT,C,C"
	crlutil -I -i ssl/nss/root.crl -d $@ -B
	crlutil -I -i ssl/nss/server.crl -d $@ -B

ssl/nss/root+server_ca.crt__root+server.crldir.db: ssl/root+server_ca.crt
	$(MKDIR_P) $@
	certutil -d "sql:$@" -N --empty-password
	certutil -d "sql:$@" -A -n ssl/root+server_ca.crt -i ssl/root+server_ca.crt -t "CT,C,C"
	crlutil -I -i ssl/nss/root.crl -d $@ -B
	for c in $(shell ls ssl/root+server-crldir) ; do \
		echo $${c} ; \
		openssl crl -in ssl/root+server-crldir/$${c} -outform der -out ssl/nss/$${c} ; \
		crlutil -I -i ssl/nss/$${c} -d $@ -B ; \
	done

# pk12util won't preserve the password when importing the password protected
# key, the password must be set on the database *before* importing it as the
# password in the pkcs12 envelope will be dropped.
ssl/nss/server-cn-only.crt__server-password.key.db: ssl/server-cn-only.crt
	$(MKDIR_P) $@
	echo "secret1" > password.txt
	certutil -d "sql:$@" -N -f password.txt
	certutil -d "sql:$@" -A -n ssl/server-cn-only.crt -i ssl/server-cn-only.crt -t "CT,C,C" -f password.txt
	certutil -d "sql:$@" -A -n server_ca.crt -i ssl/server_ca.crt -t "CT,C,C" -f password.txt
	certutil -d "sql:$@" -A -n root_ca.crt -i ssl/root_ca.crt -t "CT,C,C" -f password.txt
	certutil -d "sql:$@" -A -n client_ca.crt -i ssl/client_ca.crt -t "CT,C,C" -f password.txt
	openssl pkcs12 -export -out ssl/nss/server-password.pfx -inkey ssl/server-password.key -in ssl/server-cn-only.crt -certfile ssl/server_ca.crt -passin 'pass:secret1' -passout 'pass:secret1'
	pk12util -i ssl/nss/server-password.pfx -d "sql:$@" -W 'secret1' -K 'secret1'

ssl/nss/server-cn-only.crt__server-cn-only.key.db: ssl/server-cn-only.crt ssl/server-cn-only.key
	$(MKDIR_P) $@
	certutil -d "sql:$@" -N --empty-password
	certutil -d "sql:$@" -A -n ssl/server-cn-only.crt -i ssl/server-cn-only.crt -t "CT,C,C"
	certutil -d "sql:$@" -A -n server_ca.crt -i ssl/server_ca.crt -t "CT,C,C"
	certutil -d "sql:$@" -A -n root_ca.crt -i ssl/root_ca.crt -t "CT,C,C"
	openssl pkcs12 -export -out ssl/nss/server-cn-only.pfx -inkey ssl/server-cn-only.key -in ssl/server-cn-only.crt -certfile ssl/server_ca.crt -passout pass:
	pk12util -i ssl/nss/server-cn-only.pfx -d "sql:$@" -W ''

ssl/nss/server-cn-only.crt__server-cn-only.key.crldir.db: ssl/nss/server-cn-only.crt__server-cn-only.key.db
	cp -R $< $@
	for c in $(shell ls ssl/root+client-crldir) ; do \
		echo $${c} ; \
		openssl crl -in ssl/root+client-crldir/$${c} -outform der -out ssl/nss/$${c} ; \
		crlutil -I -i ssl/nss/$${c} -d $@ -B ; \
	done

ssl/nss/server-multiple-alt-names.crt__server-multiple-alt-names.key.db: ssl/server-multiple-alt-names.crt
	$(MKDIR_P) $@
	certutil -d "sql:$@" -N --empty-password
	certutil -d "sql:$@" -A -n ssl/server-multiple-alt-names.crt -i ssl/server-multiple-alt-names.crt -t "CT,C,C"
	certutil -d "sql:$@" -A -n server_ca.crt -i ssl/server_ca.crt -t "CT,C,C"
	certutil -d "sql:$@" -A -n root_ca.crt -i ssl/root_ca.crt -t "CT,C,C"
	certutil -d "sql:$@" -A -n client_ca.crt -i ssl/client_ca.crt -t "CT,C,C"
	openssl pkcs12 -export -out ssl/nss/server-multiple-alt-names.pfx -inkey ssl/server-multiple-alt-names.key -in ssl/server-multiple-alt-names.crt -certfile ssl/server-multiple-alt-names.crt -passout pass:
	pk12util -i ssl/nss/server-multiple-alt-names.pfx -d "sql:$@" -W ''

ssl/nss/server-single-alt-name.crt__server-single-alt-name.key.db: ssl/server-single-alt-name.crt
	$(MKDIR_P) $@
	certutil -d "sql:$@" -N --empty-password
	certutil -d "sql:$@" -A -n ssl/server-single-alt-name.crt -i ssl/server-single-alt-name.crt -t "CT,C,C"
	certutil -d "sql:$@" -A -n server_ca.crt -i ssl/server_ca.crt -t "CT,C,C"
	certutil -d "sql:$@" -A -n root_ca.crt -i ssl/root_ca.crt -t "CT,C,C"
	certutil -d "sql:$@" -A -n client_ca.crt -i ssl/client_ca.crt -t "CT,C,C"
	openssl pkcs12 -export -out ssl/nss/server-single-alt-name.pfx -inkey ssl/server-single-alt-name.key -in ssl/server-single-alt-name.crt -certfile ssl/server-single-alt-name.crt -passout pass:
	pk12util -i ssl/nss/server-single-alt-name.pfx -d "sql:$@" -W ''

ssl/nss/server-cn-and-alt-names.crt__server-cn-and-alt-names.key.db: ssl/server-cn-and-alt-names.crt
	$(MKDIR_P) $@
	certutil -d "sql:$@" -N --empty-password
	certutil -d "sql:$@" -A -n ssl/server-cn-and-alt-names.crt -i ssl/server-cn-and-alt-names.crt -t "CT,C,C"
	certutil -d "sql:$@" -A -n server_ca.crt -i ssl/server_ca.crt -t "CT,C,C"
	certutil -d "sql:$@" -A -n root_ca.crt -i ssl/root_ca.crt -t "CT,C,C"
	certutil -d "sql:$@" -A -n client_ca.crt -i ssl/client_ca.crt -t "CT,C,C"
	openssl pkcs12 -export -out ssl/nss/server-cn-and-alt-names.pfx -inkey ssl/server-cn-and-alt-names.key -in ssl/server-cn-and-alt-names.crt -certfile ssl/server-cn-and-alt-names.crt -passout pass:
	pk12util -i ssl/nss/server-cn-and-alt-names.pfx -d $@ -W ''

ssl/nss/server-no-names.crt__server-no-names.key.db: ssl/server-no-names.crt
	$(MKDIR_P) $@
	certutil -d "sql:$@" -N --empty-password
	certutil -d "sql:$@" -A -n ssl/server-no-names.crt -i ssl/server-no-names.crt -t "CT,C,C"
	certutil -d "sql:$@" -A -n server_ca.crt -i ssl/server_ca.crt -t "CT,C,C"
	certutil -d "sql:$@" -A -n root_ca.crt -i ssl/root_ca.crt -t "CT,C,C"
	certutil -d "sql:$@" -A -n client_ca.crt -i ssl/client_ca.crt -t "CT,C,C"
	openssl pkcs12 -export -out ssl/nss/server-no-names.pfx -inkey ssl/server-no-names.key -in ssl/server-no-names.crt -certfile ssl/server-no-names.crt -passout pass:
	pk12util -i ssl/nss/server-no-names.pfx -d "sql:$@" -W ''

ssl/nss/server-revoked.crt__server-revoked.key.db: ssl/server-revoked.crt
	$(MKDIR_P) $@
	certutil -d "sql:$@" -N --empty-password
	certutil -d "sql:$@" -A -n ssl/server-revoked.crt -i ssl/server-revoked.crt -t "CT,C,C"
	certutil -d "sql:$@" -A -n server_ca.crt -i ssl/server_ca.crt -t "CT,C,C"
	certutil -d "sql:$@" -A -n root_ca.crt -i ssl/root_ca.crt -t "CT,C,C"
	certutil -d "sql:$@" -A -n client_ca.crt -i ssl/client_ca.crt -t "CT,C,C"
	openssl pkcs12 -export -out ssl/nss/server-revoked.pfx -inkey ssl/server-revoked.key -in ssl/server-revoked.crt -certfile ssl/server-revoked.crt -passout pass:
	pk12util -i ssl/nss/server-revoked.pfx -d "sql:$@" -W ''


# Client certificate, signed by client CA
ssl/nss/client.crt__client.key.db: ssl/client.crt
	$(MKDIR_P) $@
	certutil -d "sql:$@" -N --empty-password
	certutil -d "sql:$@" -A -n ssl/client.crt -i ssl/client.crt -t "CT,C,C"
	certutil -d "sql:$@" -A -n client_ca.crt -i ssl/client_ca.crt -t "CT,C,C"
	certutil -d "sql:$@" -A -n root+server_ca.crt -i ssl/root+server_ca.crt -t "CT,C,C"
	openssl pkcs12 -export -out ssl/nss/client.pfx -inkey ssl/client.key -in ssl/client.crt -certfile ssl/client_ca.crt -passout pass:
	pk12util -i ssl/nss/client.pfx -d "sql:$@" -W ''

ssl/nss/client_ext.crt__client_ext.key.db: ssl/client_ext.crt
	$(MKDIR_P) $@
	certutil -d "sql:$@" -N --empty-password
	certutil -d "sql:$@" -A -n ssl/client_ext.crt -i ssl/client_ext.crt -t "CT,C,C"
	certutil -d "sql:$@" -A -n client_ca.crt -i ssl/client_ca.crt -t "CT,C,C"
	certutil -d "sql:$@" -A -n root+server_ca.crt -i ssl/root+server_ca.crt -t "CT,C,C"
	openssl pkcs12 -export -out ssl/nss/client_ext.pfx -inkey ssl/client_ext.key -in ssl/client_ext.crt -certfile ssl/client_ca.crt -passout pass:
	pk12util -i ssl/nss/client_ext.pfx -d "sql:$@" -W ''

# Client certificate with encrypted key, signed by client CA
ssl/nss/client.crt__client-encrypted-pem.key.db: ssl/client.crt
	$(MKDIR_P) $@
	echo 'dUmmyP^#+' > $@.pass
	certutil -d "sql:$@" -N -f $@.pass
	certutil -d "sql:$@" -A -f $@.pass -n ssl/client.crt -i ssl/client.crt -t "CT,C,C"
	certutil -d "sql:$@" -A -f $@.pass -n client_ca.crt -i ssl/client_ca.crt -t "CT,C,C"
	certutil -d "sql:$@" -A -f $@.pass -n root+server_ca.crt -i ssl/root+server_ca.crt -t "CT,C,C"
	openssl pkcs12 -export -out ssl/nss/client-encrypted-pem.pfx -inkey ssl/client-encrypted-pem.key -in ssl/client.crt -certfile ssl/client_ca.crt -passin pass:'dUmmyP^#+' -passout pass:'dUmmyP^#+'
	pk12util -i ssl/nss/client-encrypted-pem.pfx -d "sql:$@" -W 'dUmmyP^#+' -k $@.pass

ssl/nss/client-revoked.crt__client-revoked.key.db: ssl/client-revoked.crt
	$(MKDIR_P) $@
	certutil -d "sql:$@" -N --empty-password
	certutil -d "sql:$@" -A -n ssl/client-revoked.crt -i ssl/client-revoked.crt -t "CT,C,C"
	certutil -d "sql:$@" -A -n client_ca.crt -i ssl/client_ca.crt -t "CT,C,C"
	openssl pkcs12 -export -out ssl/nss/client-revoked.pfx -inkey ssl/client-revoked.key -in ssl/client-revoked.crt -certfile ssl/client_ca.crt -passout pass:
	pk12util -i ssl/nss/client-revoked.pfx -d "sql:$@" -W ''

# Client certificate, signed by client CA
ssl/nss/client+client_ca.crt__client.key.db: ssl/client+client_ca.crt
	$(MKDIR_P) $@
	certutil -d "sql:$@" -N --empty-password
	certutil -d "sql:$@" -A -n ssl/client+client_ca.crt -i ssl/client+client_ca.crt -t "CT,C,C"
	certutil -d "sql:$@" -A -n ssl/root+server_ca.crt -i ssl/root+server_ca.crt -t "CT,C,C"
	openssl pkcs12 -export -out ssl/nss/client.pfx -inkey ssl/client.key -in ssl/client.crt -certfile ssl/client_ca.crt -passout pass:
	pk12util -i ssl/nss/client.pfx -d "sql:$@" -W ''

ssl/nss/client.crl: ssl/client.crl
	openssl crl -in $^ -outform der -out $@

ssl/nss/server.crl: ssl/server.crl
	openssl crl -in $^ -outform der -out $@

ssl/nss/root.crl: ssl/root.crl
	openssl crl -in $^ -outform der -out $@

ssl/nss/root+client.crl: ssl/root+client.crl
	openssl crl -in $^ -outform der -out $@

#### NSS specific certificates and keys

ssl/nss/native_ca-%.db:
	$(MKDIR_P) ssl/nss/native_ca-$*.db
	certutil -N -d "sql:ssl/nss/native_ca-$*.db/" --empty-password
	echo y > nss_ca_params.txt
	echo 10 >> nss_ca_params.txt
	echo y >> nss_ca_params.txt
	cat nss_ca_params.txt | certutil -S -d "sql:ssl/nss/native_ca-$*.db/" -n ca-$* \
	-s "CN=Test CA for PostgreSQL SSL regression tests,OU=PostgreSQL test suite" \
	-x -k rsa -g 2048 -m 5432 -t CTu,CTu,CTu \
	--keyUsage certSigning -2 --nsCertType sslCA,smimeCA,objectSigningCA \
	-z Makefile -Z SHA256
	rm nss_ca_params.txt

ssl/nss/native_ca-%.pem: ssl/nss/native_ca-%.db
	certutil -L -d "sql:ssl/nss/native_ca-$*.db/" -n ca-$* -a > ssl/nss/native_ca-$*.pem

# Create and sign a server certificate
ssl/nss/native_server-%.db: ssl/nss/native_ca-%.pem
	$(MKDIR_P) ssl/nss/native_server-$*.db
	certutil -N -d "sql:ssl/nss/native_server-$*.db/" --empty-password
	certutil -R -d "sql:ssl/nss/native_server-$*.db/" \
		-s "CN=common-name.pg-ssltest.test,OU=PostgreSQL test suite" \
		-o ssl/nss/native_server-$*.csr -g 2048 -Z SHA256 -z Makefile
	echo 1 > nss_server_params.txt
	echo 9 >> nss_server_params.txt
	cat nss_server_params.txt | certutil -C -d "sql:ssl/nss/native_ca-$*.db/" -c ca-root -i ssl/nss/native_server-$*.csr \
		-o ssl/nss/native_server_$*.der -m 5433 --keyUsage dataEncipherment,digitalSignature,keyEncipherment \
		--nsCertType sslServer --certVersion 1 -Z SHA256
	certutil -A -d "sql:ssl/nss/native_server-$*.db/" -n ca-$* -t CTu,CTu,CTu -a -i ssl/nss/native_ca-$*.pem
	certutil -A -d "sql:ssl/nss/native_server-$*.db/" -n ssl/native_server-$*.crt -t CTu,CTu,CTu -i ssl/nss/native_server_$*.der
	rm nss_server_params.txt

# Create and sign a client certificate
ssl/nss/native_client-%.db: ssl/nss/native_ca-%.pem
	$(MKDIR_P) ssl/nss/native_client-$*.db
	certutil -N -d "sql:ssl/nss/native_client-$*.db/" --empty-password
	certutil -R -d "sql:ssl/nss/native_client-$*.db/" -s "CN=ssltestuser,OU=PostgreSQL test suite" \
		-o ssl/nss/native_client-$*.csr -g 2048 -Z SHA256 -z Makefile
	certutil -C -d "sql:ssl/nss/native_ca-$*.db/" -c ca-$* -i ssl/nss/native_client-$*.csr -o ssl/nss/native_client-$*.der \
		-m 5434 --keyUsage keyEncipherment,dataEncipherment,digitalSignature --nsCertType sslClient \
		--certVersion 1 -Z SHA256
	certutil -A -d "sql:ssl/nss/native_client-$*.db" -n ca-$* -t CTu,CTu,CTu -a -i ssl/nss/native_ca-$*.pem
	certutil -A -d "sql:ssl/nss/native_client-$*.db" -n native_client-$* -t CTu,CTu,CTu -i ssl/nss/native_client-$*.der

.PHONY: nssfiles-clean
nssfiles-clean:
	rm -rf ssl/nss

# The difference between the below clean targets and nssfiles-clean is that the
# clean targets will be run during a "standard" recursive clean run from the
# main build tree. The nssfiles-clean target must be run explicitly from this
# directory.
.PHONY: clean distclean maintainer-clean
clean distclean maintainer-clean:
	rm -rf ssl/nss

