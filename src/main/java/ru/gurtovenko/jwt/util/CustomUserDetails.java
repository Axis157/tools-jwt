package ru.gurtovenko.jwt.util;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;

public class CustomUserDetails implements UserDetails {

    private String accessToken;

    private String profileId;

    private String requestId;

    public CustomUserDetails(String accessToken) {
        this(accessToken, null);
    }

    public CustomUserDetails(String accessToken,
                             String requestId) {
        this.accessToken = accessToken;
        this.requestId = requestId;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    public String getProfileUid() {
        return profileId;
    }

    public void setProfileUid(String profileId) {
        this.profileId = profileId;
    }

    public String getRequestId() {
        return requestId;
    }

    public void setRequestId(String requestId) {
        this.requestId = requestId;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return null;
    }

    @Override
    public String getPassword() {
        return null;
    }

    @Override
    public String getUsername() {
        return null;
    }

    @Override
    public boolean isAccountNonExpired() {
        return false;
    }

    @Override
    public boolean isAccountNonLocked() {
        return false;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return false;
    }

    @Override
    public boolean isEnabled() {
        return false;
    }

    @Override
    public String toString() {
        return "CustomUserDetails{" +
                "accessToken='" + accessToken + '\'' +
                ", profileId='" + profileId + '\'' +
                ", requestId='" + requestId + '\'' +
                '}';
    }
}
