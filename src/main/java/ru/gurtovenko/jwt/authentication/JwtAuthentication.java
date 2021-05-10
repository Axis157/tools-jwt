package ru.gurtovenko.jwt.authentication;

import ru.gurtovenko.jwt.dto.payload.AuthorizationPayload;

public interface JwtAuthentication<T extends AuthorizationPayload> {

    String getSubject();

    void setSubject(String subject);

    Long getValidUntil();

    void setValidUntil(Long validUntil);

    T getPayload();

    void setPayload(T payload);
}
