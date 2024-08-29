package provider;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.ws.rs.core.Response;
import org.keycloak.OAuthErrorException;
import org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider;
import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.KeycloakSession;

public class NaverIdentityProvider extends AbstractOAuth2IdentityProvider implements SocialIdentityProvider{
    private static final String AUTH_URL = "https://nid.naver.com/oauth2.0/authorize";
    private static final String TOKEN_URL = "https://nid.naver.com/oauth2.0/token";
    private static final String PROFILE_URL = "https://openapi.naver.com/v1/nid/me";

    public NaverIdentityProvider(KeycloakSession session, OAuth2IdentityProviderConfig config) {
        super(session, config);
        config.setAuthorizationUrl(AUTH_URL);
        config.setTokenUrl(TOKEN_URL);
        config.setUserInfoUrl(PROFILE_URL);

    }

    @Override
    protected String getDefaultScopes() {
        return "";
    }

    @Override
    protected BrokeredIdentityContext extractIdentityFromProfile(EventBuilder event, JsonNode profile) {
        BrokeredIdentityContext user = new BrokeredIdentityContext(getJsonProperty(profile, "id"), getConfig());
        user.setIdp(this);
        user.setId(profile.get("response").get("id").asText());
        AbstractJsonUserAttributeMapper.storeUserProfileForMapper(user, profile, getConfig().getAlias());
        return user;
    }

    @Override
    protected String getProfileEndpointForValidation(EventBuilder event) {
        return PROFILE_URL;
    }

    @Override
    protected BrokeredIdentityContext doGetFederatedIdentity(String accessToken) {
        try (SimpleHttp.Response response = SimpleHttp.doGet(PROFILE_URL, session)
                .header("Authorization", "Bearer " + accessToken)
                .header("Accept", "application/json")
                .asResponse()) {
            Response.Status.Family family = Response.Status.fromStatusCode(response.getStatus()).getFamily();
            if (Response.Status.fromStatusCode(response.getStatus()).getFamily() != Response.Status.Family.SUCCESSFUL) {
                logger.warnf("Profile endpoint returned an error (%d): %s", response.getStatus(), response.asString());
                throw new IdentityBrokerException("Profile could not be retrieved from the github endpoint");
            }
            JsonNode profile = response.asJson();
            BrokeredIdentityContext user = new BrokeredIdentityContext(profile.get("response").get("id").asText(), getConfig());
            user.setIdp(this);
            System.out.println("user = " + user.getId());
            return user;
        } catch (Exception e) {
            throw new IdentityBrokerException("흠 그냥 터져 버림 doGet 에서 터진 듯함" + accessToken + "HeHe:)", e);
        }
    }

}
