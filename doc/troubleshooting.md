# Troubleshooting

A more complete, user-friendly troubleshooting document is TODO.

## Log request bodies

Drasl will log the bodies of HTTP requests to stdout if the `DRASL_DEBUG` environment variable is set:

```
export DRASL_DEBUG=1
drasl
```

## How to use mitmproxy to intercept HTTPS requests from the Minecraft Client

[mitmproxy](https://mitmproxy.org) is a powerful debugging tool. Using it to intercept HTTPS requests from Java requires a little extra work since Java keeps its own store of trusted CA root certificates, and you'll need to tell Java to trust the mitmproxy CA certificate.

These instructions assume familiarity with the command line and are written for Linux. Other platforms may require different commands, but the general procedure will be the same.

1. Run `mitmproxy`:

```
mitmproxy
```

2. Make a copy of the Java cacert keystore somewhere you can modify it:

```
cp "$(dirname "$(readlink -f "$(which java)")")/../lib/security/cacerts" ~/cacerts

# The above command might expand to something like:
cp  /usr/lib/jvm/java-21-openjdk-21.0.4.0.7-2.fc40.x86_64/lib/security/cacerts ~/cacerts
```

3. Make sure your keystore is writeable:

```
chmod +w ~/cacerts
```

4. Add the mitmproxy CA certificate to your keystore using `keytool`:

```
keytool -import -trustcacerts -noprompt -file ~/.mitmproxy/mitmproxy-ca-cert.pem -alias mitmproxy -keystore ~/cacerts
```

5. Configure the Minecraft client to use mitmproxy and your customized keystore. In Fjord Launcher or Prism Launcher, you can go to Edit Instance → Settings → Java arguments and add the following. Note that `/home/CHANGEME/cacerts` should be replaced with the path to your copy of the keystore, but `changeit` is the default password for the keystore used by Java and should be included verbatim.

```
-Djavax.net.ssl.trustStore=/home/CHANGEME/cacerts -Djavax.net.ssl.trustStorePassword=changeit -Dhttp.proxyHost=localhost -Dhttp.proxyPort=8080 -Dhttps.proxyHost=localhost -Dhttps.proxyPort=8080
```

<!-- This doesn't work on the server... I think we need to make a Java agent or mod to patch Java URL to always use the default proxy

6. Configure the Minecraft server to use mitmproxy by passing these same arguments to the Minecraft server when you launch it. For example, the full command you use to start the server might be:

```
java -Xmx1024M -Xms1024M \
  -Djavax.net.ssl.trustStore=/home/CHANGEME/cacerts -Djavax.net.ssl.trustStorePassword=changeit -Dhttp.proxyHost=localhost -Dhttp.proxyPort=8080 -Dhttps.proxyHost=localhost -Dhttps.proxyPort=8080 \
  -Dminecraft.api.env=custom \
  -Dminecraft.api.auth.host=https://drasl.unmojang.org/auth \
  -Dminecraft.api.account.host=https://drasl.unmojang.org/account \
  -Dminecraft.api.session.host=https://drasl.unmojang.org/session \
  -Dminecraft.api.services.host=https://drasl.unmojang.org/services \
  -jar server.jar nogui
```

-->
