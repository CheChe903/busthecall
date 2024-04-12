package capston.busthecall.support.context;

import capston.busthecall.security.context.TokenAuditHolder;
import lombok.experimental.UtilityClass;
import org.springframework.security.core.userdetails.UserDetails;

@UtilityClass
public class MemberIdAuditHolder {

    public static Long get() {
        UserDetails userDetails = TokenAuditHolder.get();
        return Long.parseLong(userDetails.getUsername());
    }
}
