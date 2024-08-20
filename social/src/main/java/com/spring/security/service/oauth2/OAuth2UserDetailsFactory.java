package com.spring.security.service.oauth2;

import java.util.Map;

import com.spring.security.entity.Provider;
import com.spring.security.exception.BaseException;

public class OAuth2UserDetailsFactory {

    public static OAuth2UserDetails getOAuth2User(String registrationId, Map<String, Object> attributes) {
        if (registrationId.equalsIgnoreCase(Provider.google.toString())) {
            return new OAuth2GoogleUser(attributes);
        } else if (registrationId.equalsIgnoreCase(Provider.facebook.toString())) {
            return new OAuth2FacebookUser(attributes);
        } else if (registrationId.equalsIgnoreCase(Provider.github.toString())) {
            return new OAuth2GitHubUser(attributes);
        } else {
            throw new BaseException("400", "Sorry! Login with " + registrationId + " is not supported yet.");
        }
    }

}
