package ru.gurtovenko.jwt.authentication;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import ru.gurtovenko.jwt.dto.payload.AuthorizationPayload;

import java.util.Collection;

public abstract class BasicAuthenticationToken<T extends AuthorizationPayload> extends AbstractAuthenticationToken
        implements JwtAuthentication<T> {

    private T payload;

    private String subject;

    private Long validUntil;

    public BasicAuthenticationToken(Collection<? extends GrantedAuthority> authorities,
                                    T payload,
                                    String subject,
                                    Long validUntil) {
        super(authorities);

        this.payload = payload;
        this.subject = subject;
        this.validUntil = validUntil;
    }

    public abstract boolean validate();

    @Override
    public String getSubject() {
        return subject;
    }

    @Override
    public void setSubject(String subject) {
        this.subject = subject;
    }

    @Override
    public Long getValidUntil() {
        return validUntil;
    }

    @Override
    public void setValidUntil(Long validUntil) {
        this.validUntil = validUntil;
    }

    @Override
    public T getPayload() {
        return payload;
    }

    @Override
    public void setPayload(T payload) {
        this.payload = payload;
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return payload;
    }

    @Override
    public String toString() {
        return "{payload=" + payload +
                ", subject='" + subject + '\'' +
                ", validUntil=" + validUntil +
                '}';
    }

}
