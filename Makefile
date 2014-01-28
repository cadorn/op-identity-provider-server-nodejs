
install:
	npm install
	# If installed in dev context we link the client library.
	if [ -d "../github.com+openpeer+op-identity-provider-client" ]; then \
		rm -Rf node_modules/op-identity-provider-client; \
		ln -s ../../github.com+openpeer+op-identity-provider-client node_modules/op-identity-provider-client; \
	fi
	if [ -d "../github.com+openpeer+opjs-primitives" ]; then \
		rm -Rf node_modules/opjs-primitives; \
		ln -s ../../github.com+openpeer+opjs-primitives node_modules/opjs-primitives; \
	fi

.PHONY: install
