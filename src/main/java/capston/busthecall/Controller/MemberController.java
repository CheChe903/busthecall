package capston.busthecall.Controller;

import capston.busthecall.domain.Member;
import capston.busthecall.domain.dto.request.LoginUserRequest;
import capston.busthecall.domain.dto.request.SaveUserRequest;
import capston.busthecall.domain.dto.response.SavedUserInfo;
import capston.busthecall.service.LoadUserService;
import capston.busthecall.service.SavedUserService;
import capston.busthecall.support.ApiResponse;
import capston.busthecall.support.ApiResponseGenerator;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import jakarta.validation.Valid;

@RestController
@RequiredArgsConstructor
@Slf4j
@RequestMapping("/api/v1/members")
public class MemberController {

    private final SavedUserService savedUserService;
    private final LoadUserService loadUserService;

    @PostMapping(value = "/register")
    public ApiResponse<ApiResponse.SuccessBody<SavedUserInfo>> register(
            @Valid @RequestBody SaveUserRequest request)
    {
        SavedUserInfo res = savedUserService.excute(request);
        return ApiResponseGenerator.success(res, HttpStatus.CREATED);
    }

//    @PostMapping(value="/login")
//    public ApiResponse<ApiResponse.SuccessBody<SavedUserInfo>> login
//            (@Valid @RequestBody LoginUserRequest request)
//    {
//        SavedUserInfo res = loadUserService.execute(request);
//        return ApiResponseGenerator.success(res, HttpStatus.CREATED);
//    }


}
