package capston.busthecall.domain.dto.request;

import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
@Getter
public class DriverLogInRequest {

    private String email;
    private String password;
}
