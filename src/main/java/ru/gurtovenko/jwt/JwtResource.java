package ru.gurtovenko.jwt;

import io.jsonwebtoken.SignatureAlgorithm;

public interface JwtResource {
    String AUTH_TOKEN_HEADER_NAME = "Authorization";

    String JWT_PREFIX = "Bearer ";

    String PAYLOAD_CLAIM_NAME = "info";

    String AUTHORITIES_CLAIM_NAME = "list";

    String AUTHORIZED_CLAIM_NAME = "auth";

    SignatureAlgorithm SIGNATURE_ALGORITHM = SignatureAlgorithm.HS512;

    SignatureAlgorithm SHORT_SIGNATURE_ALGORITHM = SignatureAlgorithm.HS256;
}
