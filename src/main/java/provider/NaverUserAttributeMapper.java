package provider;

import org.keycloak.broker.oidc.mappers.UserAttributeMapper;

public class NaverUserAttributeMapper extends UserAttributeMapper {

    private static final String[] cp = new String[] { NaverIdentityProviderFactory.PROVIDER_ID };

    @Override
    public String[] getCompatibleProviders() {
        return cp;
    }


    @Override
    public String getId() {
        return "naver-user-attribute-mapper";
    }
}
