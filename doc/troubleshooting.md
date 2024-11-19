# Troubleshooting

A more complete, user-friendly troubleshooting document is TODO.

## Log request bodies

Drasl will log the bodies of HTTP requests to stdout if the `DRASL_DEBUG` environment variable is set:

```
export DRASL_DEBUG=1
drasl
```

## How to use mitmproxy to intercept HTTPS requests from the Minecraft client and Minecraft server

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

5. Configure the Minecraft client to proxy requests through mitmproxy and use your customized keystore. In Fjord Launcher or Prism Launcher, you can go to Edit Instance → Settings → Java arguments and add the following. Note that `/home/MYUSER/cacerts` should be replaced with the path to your copy of the keystore, but `changeit` is the default password for the keystore used by Java and should be included verbatim.

   ```
   -Djavax.net.ssl.trustStore=/home/MYUSER/cacerts -Djavax.net.ssl.trustStorePassword=changeit -Dhttp.proxyHost=localhost -Dhttp.proxyPort=8080 -Dhttps.proxyHost=localhost -Dhttps.proxyPort=8080
   ```

   If everything is working, mitmproxy should intercept a request to https://drasl.example.com/session/session/minecraft/join every time the client joins a server.

6. On the Minecraft server, you'll need to add the same arguments AND use [Java Proxy Fix](https://github.com/unmojang/java-proxy-fix) to make the server respect them. Download the [latest version](https://github.com/unmojang/java-proxy-fix/releases) of Java Proxy Fix and place it next to your Minecraft server JAR. Then, use something like the following command to start the server. Again, make sure to change `/home/MYUSER/cacerts` to the path to your copy of the keystore, but do not change `changeit`:

   ```
   java -Xmx1024M -Xms1024M \
     -Djavax.net.ssl.trustStore=/home/MYUSER/cacerts -Djavax.net.ssl.trustStorePassword=changeit -Dhttp.proxyHost=localhost -Dhttp.proxyPort=8080 -Dhttps.proxyHost=localhost -Dhttps.proxyPort=8080 \
     -Dminecraft.api.env=custom \
     -Dminecraft.api.auth.host=https://drasl.example.com/auth \
     -Dminecraft.api.account.host=https://drasl.example.com/account \
     -Dminecraft.api.session.host=https://drasl.example.com/session \
     -Dminecraft.api.services.host=https://drasl.example.com/services \
     -javaagent:ProxyFix-1.0-SNAPSHOT-jar-with-dependencies.jar \
     -jar server.jar nogui
   ```

   If everything is working, you should see messages from ProxyFix in the server log, and mitmproxy should intercept a request to https://drasl.example.com/session/session/minecraft/hasJoined every time a client joins the server.
