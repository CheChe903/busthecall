package capston.busthecall.domain.dto.request;

import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
@Getter
public class DriverJoinRequest {

    private String name;
    private String email;
    private String password;
}
