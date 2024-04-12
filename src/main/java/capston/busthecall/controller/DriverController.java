package capston.busthecall.controller;

import capston.busthecall.domain.dto.request.DriverJoinRequest;
import capston.busthecall.domain.dto.request.DriverLogInRequest;
import capston.busthecall.service.DriverService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/drivers")
public class DriverController {

    private final DriverService driverService;

    @PostMapping("/join")
    public ResponseEntity<String> join(@RequestBody DriverJoinRequest dto) {
        driverService.join(dto.getName(), dto.getEmail(), dto.getPassword());
        return ResponseEntity.ok().body("회원 가입 성공!");
    }

    /*@PostMapping("/login")
    public ResponseEntity<String> logIn(@RequestBody DriverLogInRequest dto) {
        //String token = driverService.logIn(dto.getEmail(), dto.getPassword());
        return ResponseEntity.ok().body("token");
    }*/
}
