package capston.busthecall.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
public class EncoderConfig {

    /**
     * Security 를 이용해서 회원가입, 로그인 하는 경우
     * 항상 비밀번호를 캐시로 암호화해서 검증하고 진행.
     */
    @Bean
    public BCryptPasswordEncoder encoder() {

        return new BCryptPasswordEncoder();
    }
}
