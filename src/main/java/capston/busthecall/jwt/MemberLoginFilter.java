package capston.busthecall.jwt;

import capston.busthecall.domain.dto.response.SavedUserInfo;
import capston.busthecall.support.ApiResponse;
import capston.busthecall.support.ApiResponseGenerator;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.util.Map;

/**
 * 요청을 가로채서 요청 값을 검증
 */
public class MemberLoginFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;

    public MemberLoginFilter(AuthenticationManager authenticationManager, JwtUtil jwtUtil) {
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
        this.setFilterProcessesUrl("/api/v1/members/login");
        this.setAuthenticationManager(authenticationManager);
    }


//    @PostMapping(value="/login")
//    public ApiResponse<ApiResponse.SuccessBody<SavedUserInfo>> login
//            (@Valid @RequestBody LoginUserRequest request)
//    {
//        SavedUserInfo res = loadUserService.execute(request);
//        return ApiResponseGenerator.success(res, HttpStatus.CREATED);
//    }
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        //클라이언트 요청에서 email, password 추출
        Map<String, String> requestBody = obtainBody(request);
        String email = requestBody.get("email");
        String password = requestBody.get("password");

        email = email.trim();

        //스프링 시큐리티에서 email, password 검증하기 위해서는 token 에 담아야 함.
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(email, password, null);

        setDetails(request, authToken);

        // token 에 담은 검증을 위한 AuthenticationManager 전달.
        return authenticationManager.authenticate(authToken);
    }

    //로그인 성공시 실행하는 메소드 (여기서 JWT를 발급하면 됨)
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) {
        // 사용자 인증 정보를 바탕으로 JWT 생성
        String token = jwtUtil.generateToken(authentication);

        // 로그인한 사용자 정보 가져오기 (예시로 사용자 정보를 담고 있는 SavedUserInfo 객체를 생성)
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        SavedUserInfo savedUserInfo = new SavedUserInfo(userDetails.getUsername(), token); // 예시 구조

        // ApiResponseGenerator를 사용하여 성공 응답 생성
        ApiResponse<ApiResponse.SuccessBody<SavedUserInfo>> apiResponse = ApiResponseGenerator.success(savedUserInfo, HttpStatus.OK);

        // 응답에 JWT를 포함시키기
        response.setHeader("Authorization", "Bearer " + token);

        // 응답 본문에 ApiResponse 객체를 JSON 형태로 변환하여 포함시키기
        ObjectMapper objectMapper = new ObjectMapper();
        response.setContentType("application/json;charset=UTF-8");
        try {
            response.getWriter().write(objectMapper.writeValueAsString(apiResponse));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }


    //로그인 실패시 실행하는 메소드
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) {
        response.setStatus(401);
    }

    protected Map<String, String> obtainBody(HttpServletRequest request) {
        try {
            ObjectMapper objectMapper = new ObjectMapper();
            return objectMapper.readValue(request.getInputStream(), Map.class);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
