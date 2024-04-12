package capston.busthecall.service;

import capston.busthecall.domain.Driver;
import capston.busthecall.exception.AppException;
import capston.busthecall.exception.ErrorCode;
import capston.busthecall.jwt.JwtUtil;
import capston.busthecall.repository.DriverRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class DriverService {

    private final DriverRepository driverRepository;
    private final BCryptPasswordEncoder encoder;

    @Value("${jwt.secret}")
    private String key;
    private Long expiredTimeMs = 1000 * 60 * 60L;

    public String join(String name, String email, String password) {

        //email 중복 체크
        driverRepository.findByEmail(email)
                .ifPresent(driver -> {
                    throw new AppException(ErrorCode.EMAIL_DUPLICATED, email + "이 존재합니다.");
                });

        //저장
        Driver driver = Driver.builder()
                .name(name)
                .email(email)
                .password(encoder.encode(password))
                .role("ROLE_USER")
                .build();

        driverRepository.save(driver);

        return "SUCCESS";
    }
/*
    public String logIn(String email, String password) {
        //email 없음
        Driver selectDriver = driverRepository.findByEmail(email)
                .orElseThrow(() -> new AppException(ErrorCode.EMAIL_NOTFOUND, email + "이 없습니다."));

        //password 틀림
        if (!encoder.matches(password, selectDriver.getPassword())) {
            throw new AppException(ErrorCode.INVALID_PASSWORD, "패스워드를 잘못 입력 했습니다.");
        }

//        JwtUtil.createJwt(selectDriver.getEmail(), key, expiredTimeMs)

        //토큰 발행
        return "token";
    }
*/
}
