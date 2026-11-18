package org.apache.shiro.spring.boot;

import org.apache.shiro.authc.credential.AllowAllCredentialsMatcher;
import org.apache.shiro.authc.credential.CredentialsMatcher;
import org.apache.shiro.authz.permission.PermissionResolver;
import org.apache.shiro.authz.permission.RolePermissionResolver;
import org.apache.shiro.event.EventBus;
import org.apache.shiro.event.support.DefaultEventBus;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.realm.SimpleAccountRealm;
import org.apache.shiro.spring.boot.utils.JakartaFilterAdapter;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Configuration;
import win.zqxu.shiro.oltu.client.OAuthAuthorizeRealm;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class ShiroOltuBootIntegrationTest {

    private final WebApplicationContextRunner contextRunner = new WebApplicationContextRunner()
            .withUserConfiguration(Application.class)
            .withBean(EventBus.class, DefaultEventBus::new)
            .withBean(Realm.class, SimpleAccountRealm::new)
            .withBean(CredentialsMatcher.class, AllowAllCredentialsMatcher::new)
            .withPropertyValues("shiro.static-security-manager-enabled=false");

    private final WebApplicationContextRunner enabledContext = contextRunner.withPropertyValues("shiro.oltu.enabled=true", "shiro.oltu.client-id=test-client",
                        "shiro.oltu.client-secret=test-secret", "shiro.oltu.state=test-state",
                        "shiro.oltu.token-uri=https://provider.example.test/token",
                        "shiro.oltu.failure-uri=/error", "shiro.oltu.default-roles=reader",
                        "shiro.oltu.default-permissions=reports:read");

    @Test
    void bootDiscoversTheRealmAndFilterOnlyWhenEnabled() {
        contextRunner.run(context -> {
            assertThat(context).doesNotHaveBean("oltu");
            assertThat(context).doesNotHaveBean(OAuthAuthorizeRealm.class);
        });
        enabledContext
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    OAuthAuthorizeRealm realm = context.getBean(OAuthAuthorizeRealm.class);
                    assertThat(realm.getCredentialsMatcher()).isSameAs(context.getBean(CredentialsMatcher.class));
                    FilterRegistrationBean<?> filter = context.getBean("oltu", FilterRegistrationBean.class);
                    assertThat(filter.getFilter()).isInstanceOf(JakartaFilterAdapter.class);
                    assertThat(filter.isEnabled()).isFalse();
                });
    }

    @Test
    void preservesApplicationPermissionResolvers() {
        PermissionResolver permissions = mock(PermissionResolver.class);
        RolePermissionResolver roles = mock(RolePermissionResolver.class);
        enabledContext.withBean(PermissionResolver.class, () -> permissions)
                .withBean(RolePermissionResolver.class, () -> roles)
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    OAuthAuthorizeRealm realm = context.getBean(OAuthAuthorizeRealm.class);
                    assertThat(realm.getPermissionResolver()).isSameAs(permissions);
                    assertThat(realm.getRolePermissionResolver()).isSameAs(roles);
                });
    }

    @Configuration(proxyBeanMethods = false)
    @EnableAutoConfiguration
    static class Application {
    }
}
