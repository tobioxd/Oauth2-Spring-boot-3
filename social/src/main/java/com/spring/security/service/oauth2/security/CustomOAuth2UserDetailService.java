package com.spring.security.service.oauth2.security;

import java.util.HashSet;
import java.util.Optional;
import java.util.stream.Collectors;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import com.spring.security.entity.User;
import com.spring.security.exception.BaseException;
import com.spring.security.repository.RoleRepository;
import com.spring.security.repository.UserRepository;
import com.spring.security.service.oauth2.OAuth2UserDetails;
import com.spring.security.service.oauth2.OAuth2UserDetailsFactory;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class CustomOAuth2UserDetailService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;

    private final RoleRepository roleRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User user = super.loadUser(userRequest);

        try {

            return checkingOAuth2User(userRequest, user);

        } catch (OAuth2AuthenticationException e) {
            throw new BaseException("400", e.getMessage());
        } catch (Exception e) {
            throw new BaseException("400", e.getMessage());
        }

    }

    private OAuth2User checkingOAuth2User(OAuth2UserRequest userRequest, OAuth2User oAuth2User) {
        OAuth2UserDetails oAuth2UserDetails = OAuth2UserDetailsFactory
                .getOAuth2User(userRequest.getClientRegistration().getRegistrationId(), oAuth2User.getAttributes());

        if (oAuth2UserDetails == null) {
            throw new BaseException("400", "Sorry! Login with "
                    + userRequest.getClientRegistration().getRegistrationId() + " is not supported yet.");
        }

        Optional<User> user = userRepository.findByUsernameAndProviderId(oAuth2UserDetails.getEmail(),
                userRequest.getClientRegistration().getRegistrationId());

        User userDetails;
        if (user.isPresent()) {
            userDetails = user.get();

            if (!userDetails.getProviderId().equals(userRequest.getClientRegistration().getRegistrationId())) {
                throw new BaseException("400", "Sorry! Login with "
                        + userRequest.getClientRegistration().getRegistrationId() + " is not supported yet.");
            }

            userDetails = updateExistingUser(userDetails, oAuth2UserDetails);
        } else {
            userDetails = registerNewUser(userRequest, oAuth2UserDetails);
        }

        return new OAuth2UserDetailsCustom(userDetails.getId(), userDetails.getUsername(), userDetails.getPassword(),
                userDetails.getRoles().stream().map(role -> new SimpleGrantedAuthority(role.getName()))
                        .collect(Collectors.toList()));

    }

    public User registerNewUser(OAuth2UserRequest userRequest, OAuth2UserDetails oAuth2UserDetails) {
        User user = new User();

        user.setUsername(oAuth2UserDetails.getEmail());
        user.setProviderId(userRequest.getClientRegistration().getRegistrationId());
        user.setEnabled(true);
        user.setCredentialsNonExpired(true);
        user.setAccountNonExpired(true);
        user.setAccountNonLocked(true);
        user.setRoles(new HashSet<>());

        user.getRoles().add(roleRepository.findByName("USER"));

        return userRepository.save(user);
    }

    public User updateExistingUser(User existingUser, OAuth2UserDetails oAuth2UserDetails) {
        existingUser.setUsername(oAuth2UserDetails.getEmail());

        return userRepository.save(existingUser);
    }

}
