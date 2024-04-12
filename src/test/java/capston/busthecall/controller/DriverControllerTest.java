package capston.busthecall.controller;

import capston.busthecall.domain.dto.request.DriverJoinRequest;
import capston.busthecall.exception.AppException;
import capston.busthecall.exception.ErrorCode;
import capston.busthecall.service.DriverService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest
class DriverControllerTest {

    @Autowired MockMvc mockMvc;
    @Autowired ObjectMapper objectMapper;

    @MockBean
    DriverService driverService;

    @Test
    @DisplayName("회원 가입 성공!")
    @WithMockUser
    void join() throws Exception {
        String name = "lim";
        String email = "1234@1234";
        String password = "qwer1234";

        mockMvc.perform(post("/api/v1/drivers/join")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsBytes(new DriverJoinRequest(name, email, password))))
                .andDo(print())
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("회원 가입 실패! - email 중복")
    @WithMockUser
    void joinEx_Email() throws Exception {
        String name = "lim";
        String email = "1234@1234";
        String password = "qwer1234";

        when(driverService.join(any(), any(), any()))
                .thenThrow(new AppException(ErrorCode.EMAIL_DUPLICATED, ""));

        mockMvc.perform(post("/api/v1/drivers/join")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsBytes(new DriverJoinRequest(name, email, password))))
                .andDo(print())
                .andExpect(status().isConflict());
    }
}