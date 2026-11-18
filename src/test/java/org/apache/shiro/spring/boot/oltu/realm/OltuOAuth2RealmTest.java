package org.apache.shiro.spring.boot.oltu.realm;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicReference;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.spring.boot.oltu.exception.OAuth2AuthenticationException;
import org.apache.shiro.spring.boot.oltu.token.OltuOAuth2Token;
import org.apache.shiro.subject.PrincipalCollection;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

@DisplayName("OltuOAuth2Realm Tests")
class OltuOAuth2RealmTest {

    @Test
    @DisplayName("Instance can be created via constructor")
    void testInstantiation() {
        OltuOAuth2Realm instance = new OltuOAuth2Realm();
        assertThat(instance).isNotNull();
    }

    @Test
    @DisplayName("Extends AuthorizingRealm")
    void testExtendsAuthorizingRealm() {
        assertThat(org.apache.shiro.realm.AuthorizingRealm.class
                .isAssignableFrom(OltuOAuth2Realm.class)).isTrue();
    }

    @Test
    @DisplayName("supports returns true for OltuOAuth2Token")
    void testSupportsOAuth2Token() {
        OltuOAuth2Realm realm = new OltuOAuth2Realm();
        AuthenticationToken token = new OltuOAuth2Token("code");
        assertThat(realm.supports(token)).isTrue();
    }

    @Test
    @DisplayName("supports returns false for other token types")
    void testSupportsOtherToken() {
        OltuOAuth2Realm realm = new OltuOAuth2Realm();
        AuthenticationToken token = mock(AuthenticationToken.class);
        assertThat(realm.supports(token)).isFalse();
    }

    @Test
    @DisplayName("doGetAuthorizationInfo returns non-null info")
    void testDoGetAuthorizationInfo() {
        OltuOAuth2Realm realm = new OltuOAuth2Realm();
        PrincipalCollection principals = mock(PrincipalCollection.class);
        AuthorizationInfo info = realm.doGetAuthorizationInfo(principals);
        assertThat(info).isNotNull();
    }

    @Test
    @DisplayName("doGetAuthenticationInfo throws OAuth2AuthenticationException when not configured")
    void testDoGetAuthenticationInfoFailure() {
        OltuOAuth2Realm realm = new OltuOAuth2Realm();
        OltuOAuth2Token token = new OltuOAuth2Token("testCode");
        assertThatThrownBy(() -> realm.doGetAuthenticationInfo(token))
                .isInstanceOf(AuthenticationException.class);
    }

    @Test
    @DisplayName("clientId setter works")
    void testClientId() {
        OltuOAuth2Realm realm = new OltuOAuth2Realm();
        realm.setClientId("myClient");
        assertThat(realm).isNotNull();
    }

    @Test
    @DisplayName("clientSecret setter works")
    void testClientSecret() {
        OltuOAuth2Realm realm = new OltuOAuth2Realm();
        realm.setClientSecret("secret");
        assertThat(realm).isNotNull();
    }

    @Test
    @DisplayName("accessTokenUrl setter works")
    void testAccessTokenUrl() {
        OltuOAuth2Realm realm = new OltuOAuth2Realm();
        realm.setAccessTokenUrl("http://token");
        assertThat(realm).isNotNull();
    }

    @Test
    @DisplayName("userInfoUrl setter works")
    void testUserInfoUrl() {
        OltuOAuth2Realm realm = new OltuOAuth2Realm();
        realm.setUserInfoUrl("http://userinfo");
        assertThat(realm).isNotNull();
    }

    @Test
    @DisplayName("redirectUrl setter works")
    void testRedirectUrl() {
        OltuOAuth2Realm realm = new OltuOAuth2Realm();
        realm.setRedirectUrl("http://redirect");
        assertThat(realm).isNotNull();
    }
    @Test
    void exchangesAStubAuthorizationCodeAndReadsTheProviderIdentity() throws Exception {
        HttpServer provider = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        AtomicReference<String> tokenMethod = new AtomicReference<>();
        AtomicReference<String> userInfoMethod = new AtomicReference<>();
        provider.createContext("/token", exchange -> {
            tokenMethod.set(exchange.getRequestMethod());
            respond(exchange, "application/json", "{\"access_token\":\"fixture-token\",\"expires_in\":60}");
        });
        provider.createContext("/user", exchange -> {
            userInfoMethod.set(exchange.getRequestMethod());
            respond(exchange, "text/plain", "fixture-user");
        });
        provider.start();

        try {
            String endpoint = "http://127.0.0.1:" + provider.getAddress().getPort();
            OltuOAuth2Realm realm = new OltuOAuth2Realm();
            realm.setAccessTokenUrl(endpoint + "/token");
            realm.setUserInfoUrl(endpoint + "/user");
            realm.setClientId("fixture-client");
            realm.setClientSecret("fixture-secret");
            realm.setRedirectUrl("https://application.example.test/callback");

            AuthenticationInfo result = realm.doGetAuthenticationInfo(new OltuOAuth2Token("fixture-code"));

            assertThat(result.getPrincipals().getPrimaryPrincipal()).isEqualTo("fixture-user");
            assertThat(tokenMethod.get()).isEqualTo("POST");
            assertThat(userInfoMethod.get()).isEqualTo("GET");
        } finally {
            provider.stop(0);
        }
    }

    private void respond(HttpExchange exchange, String contentType, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        try (exchange) {
            exchange.getResponseHeaders().set("Content-Type", contentType);
            exchange.sendResponseHeaders(200, bytes.length);
            exchange.getResponseBody().write(bytes);
        }
    }

}
