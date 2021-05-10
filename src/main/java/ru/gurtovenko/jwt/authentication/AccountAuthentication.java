package ru.gurtovenko.jwt.authentication;

import org.springframework.security.core.GrantedAuthority;
import ru.gurtovenko.jwt.dto.payload.AccountInfo;

import java.util.ArrayList;
import java.util.Collection;

public class AccountAuthentication extends BasicAuthenticationToken<AccountInfo> {

    public AccountAuthentication(AccountInfo accountInfo,
                                 String subject,
                                 Long validUntil) {
        this(new ArrayList<>(), accountInfo, subject, validUntil);
    }

    public AccountAuthentication(Collection<? extends GrantedAuthority> authorities,
                                 AccountInfo accountInfo,
                                 String subject,
                                 Long validUntil) {
        super(authorities, accountInfo, subject, validUntil);
    }

    @Override
    public boolean validate() {
        AccountInfo adminInfo = getPayload();

        if (adminInfo == null) {
            return false;
        }

        return adminInfo.getId() != null && adminInfo.getUsername() != null;
    }

    @Override
    public String toString() {
        return "AccountAuthentication: " + super.toString();
    }
}
