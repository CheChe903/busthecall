package capston.busthecall.service;

import capston.busthecall.domain.Driver;
import capston.busthecall.domain.dto.CustomDriverDetails;
import capston.busthecall.exception.AppException;
import capston.busthecall.exception.ErrorCode;
import capston.busthecall.repository.DriverRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class CustomDriverDetailsService implements UserDetailsService {

    private final DriverRepository driverRepository;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {

        Optional<Driver> driverOptional = driverRepository.findByEmail(email);

        if (driverOptional.isPresent()) {
            return new CustomDriverDetails(driverOptional.get());
        }

        throw new AppException(ErrorCode.EMAIL_NOTFOUND, "해당 이메일은 존재하지 않습니다.");
    }
}
