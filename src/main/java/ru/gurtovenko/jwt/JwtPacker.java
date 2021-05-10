package ru.gurtovenko.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.security.core.GrantedAuthority;
import ru.gurtovenko.jwt.authentication.BasicAuthenticationToken;
import ru.gurtovenko.jwt.dto.payload.AuthorizationPayload;

import java.io.IOException;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

public class JwtPacker implements JwtResource {

    private final static Logger logger = LogManager.getLogger(JwtPacker.class);
    private final static ObjectMapper objectMapper = new ObjectMapper();

    public static <P extends AuthorizationPayload> String compact(BasicAuthenticationToken<P> authentication,
                                                                            Date now,
                                                                            String secretKey) throws JwtException {
        return compact(authentication, now, secretKey, SIGNATURE_ALGORITHM);
    }

    public static <P extends AuthorizationPayload> String compactShort(BasicAuthenticationToken<P> authentication,
                                                                                 Date now,
                                                                                 String secretKey) throws JwtException {
        return compact(authentication, now, secretKey, SHORT_SIGNATURE_ALGORITHM);
    }

    private static <P extends AuthorizationPayload> String compact(BasicAuthenticationToken<P> authentication,
                                                                   Date now,
                                                                   String secretKey,
                                                                   SignatureAlgorithm signatureAlgorithm) throws JwtException {
        try {
            P authenticationPayload = authentication.getPayload();

            JwtBuilder jwtBuilder = Jwts.builder()
                    .setSubject(authentication.getSubject())
                    .setIssuedAt(now)
                    .setExpiration(new Date(authentication.getValidUntil()))
                    .signWith(signatureAlgorithm, secretKey);

            if (authenticationPayload != null) {
                jwtBuilder.claim(PAYLOAD_CLAIM_NAME, objectMapper.writeValueAsString(authenticationPayload));
            }

            boolean authenticated = authentication.isAuthenticated();
            if (authenticated) {
                jwtBuilder.claim(AUTHORIZED_CLAIM_NAME, objectMapper.writeValueAsString("1"));
            }

            Collection<GrantedAuthority> authorities = authentication.getAuthorities();
            if (authorities != null && !authorities.isEmpty()) {
                jwtBuilder.claim(AUTHORITIES_CLAIM_NAME,
                        objectMapper.writeValueAsString(authorities.stream().map(GrantedAuthority :: getAuthority)
                                .collect(Collectors.toList())));
            }

            return jwtBuilder.compact();
        } catch (JwtException | IOException e) {
            logger.error("Error while compacting JWT: {}. ", e.getMessage());
            throw new JwtException(e.getMessage(), e);
        }
    }
}
