package com.spring.security.service.oauth2.security;

import java.util.List;
import java.util.Map;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

public class OAuth2UserDetailsCustom implements OAuth2User, UserDetails{

    private Long id;

    private String username;

    private String password;

    private boolean accountNonExpired;

    private boolean isEnabled;

    private boolean accountNonLocked;

    private boolean credentialsNonExpired;

    private List<GrantedAuthority> authorities;

    private Map<String, Object> attributes;

    public OAuth2UserDetailsCustom(Long id, String username, String password, List<GrantedAuthority> authorities) {
        this.id = id;
        this.username = username;
        this.password = password;
        this.authorities = authorities;
    }

    @Override
    public<A> A getAttribute(String name){
        return OAuth2User.super.getAttribute(name);
    }

    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    @Override
    public String getName() {
        return String.valueOf(id);
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    public Long getId() {
        return id;
    }

    public boolean isAccountNonExpired() {
        return accountNonExpired;
    }

    public boolean isEnabled() {
        return isEnabled;
    }

    public boolean isAccountNonLocked() {
        return accountNonLocked;
    }

    public boolean isCredentialsNonExpired() {
        return credentialsNonExpired;
    }

    public List<GrantedAuthority> getAuthorities() {
        return authorities;
    }

}
