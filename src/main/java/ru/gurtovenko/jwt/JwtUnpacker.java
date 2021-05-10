package ru.gurtovenko.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.server.ServerWebExchange;
import ru.gurtovenko.jwt.authentication.AccountAuthentication;
import ru.gurtovenko.jwt.authentication.BasicAuthenticationToken;
import ru.gurtovenko.jwt.dto.payload.AccountInfo;
import ru.gurtovenko.jwt.dto.payload.AuthorizationPayload;
import ru.gurtovenko.jwt.util.CustomUserDetails;

import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class JwtUnpacker implements JwtResource {

    private final static Logger logger = LogManager.getLogger(JwtUnpacker.class);
    private final static ObjectMapper objectMapper = new ObjectMapper();

    public static BasicAuthenticationToken fetchBasicAuthentication(ServerWebExchange serverWebExchange,
                                                                   String secretKey) throws JwtException {
        ServerHttpRequest request = serverWebExchange.getRequest();
        List<String> tokens = request.getHeaders().get(HttpHeaders.AUTHORIZATION);

        if (tokens != null && !tokens.isEmpty()) {
            String token = tokens.get(0);
            return fetchBasicAuthentication(token, secretKey);
        }

        return null;
    }

    public static BasicAuthenticationToken fetchBasicAuthentication(String jsonWebToken,
                                                                  String secretKey) throws JwtException {
        BasicAuthenticationToken token = fetchAccountAuthentication(jsonWebToken, secretKey);
        if (token != null) {
            return token;
        }

        return null;
    }

    public static AccountAuthentication fetchAccountAuthentication(String token,
                                                               String secretKey) throws JwtException {
        if (token != null) {
            BasicAuthenticationToken<AccountInfo> authentication = getAuthentication(token,
                    secretKey,
                    AccountInfo.class,
                    AccountAuthentication.class);

            if (authentication != null) {
                return (AccountAuthentication) authentication;
            }
        }

        return null;
    }

    private static <T extends AuthorizationPayload> BasicAuthenticationToken<T> getAuthentication(String token,
                                                                                                 String secretKey,
                                                                                                 Class<T> payloadClass,
                                                                                                 Class<? extends BasicAuthenticationToken<T>> tokenClass) throws JwtException {
        BasicAuthenticationToken<T> basicAuthenticationToken = parse(token.replace(JWT_PREFIX, ""), secretKey, payloadClass, tokenClass);

        if (basicAuthenticationToken.validate()) {
            return basicAuthenticationToken;
        }

        return null;
    }

    private static <T extends AuthorizationPayload> BasicAuthenticationToken<T> parse(String token,
                                                                                     String secretKey,
                                                                                     Class<T> payloadClass,
                                                                                     Class<? extends BasicAuthenticationToken<T>> tokenClass) throws JwtException {
        try {
            Jws<Claims> jws = Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token);

            Claims claims = jws.getBody();
            String payloadClaim = claims.get(PAYLOAD_CLAIM_NAME, String.class);
            String authoritiesClaim = claims.get(AUTHORITIES_CLAIM_NAME, String.class);
            String authorizedClaim = claims.get(AUTHORIZED_CLAIM_NAME, String.class);

            T payload = null;
            if (StringUtils.isNotEmpty(payloadClaim)) {
                payload = objectMapper.readValue(payloadClaim, payloadClass);
            } else {
                Constructor<?> payloadConstructor = payloadClass.getConstructor();
                payload = (T) payloadConstructor.newInstance();
            }

            List<String> stringAuthorities = new ArrayList<>();
            if (StringUtils.isNotEmpty(authoritiesClaim)) {
                stringAuthorities = objectMapper.readValue(authoritiesClaim, List.class);
            }

            boolean authorized = false;
            if (StringUtils.isNotEmpty(authorizedClaim)) {
                authorized = true;
            }

            List<GrantedAuthority> authorities = new ArrayList<>();
            stringAuthorities.forEach(authority -> authorities.add(new SimpleGrantedAuthority(authority)));

            Constructor<?> tokenConstructor = tokenClass.getConstructor(Collection.class, payloadClass, String.class, Long.class);

            BasicAuthenticationToken<T> basicAuthenticationToken = (BasicAuthenticationToken<T>) tokenConstructor.newInstance(authorities,
                    payload,
                    claims.getSubject(),
                    claims.getExpiration().getTime());
            basicAuthenticationToken.setAuthenticated(authorized);

            UserDetails customUserDetails = new CustomUserDetails(token);
            basicAuthenticationToken.setDetails(customUserDetails);

            return basicAuthenticationToken;
        } catch (NoSuchMethodException | InstantiationException | IllegalAccessException | InvocationTargetException e) {
            logger.error("Bad constructor for {} JWT authentication: {}.", payloadClass, e.getMessage());
            throw new JwtException(e.getMessage(), e);
        } catch (JwtException | IOException e) {
            logger.warn("Error while parsing {} JWT: {}.", payloadClass, e.getMessage());
            throw new JwtException(e.getMessage(), e);
        }
    }
}
