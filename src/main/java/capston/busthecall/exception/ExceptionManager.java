package capston.busthecall.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * Exception 발생하면
 * @RestControllerAdvice가 달린 클래스로 온다.
 * 그다음 @ExceptionHandler() -> 해당 Exception 메소드 수행
 */
@RestControllerAdvice
public class ExceptionManager {

    /**
     * ResponseEntity<?> -> ?로 설정을 해놓으면 ResponseBody 에 어떤거든 들어갈 수 있다.
     */
    @ExceptionHandler(IllegalStateException.class)
    public ResponseEntity<?> illegalStateExceptionHandler(IllegalStateException e) {

        return ResponseEntity.status(HttpStatus.CONFLICT)
                .body(e.getMessage());
    }

    @ExceptionHandler(AppException.class)
    public ResponseEntity<?> appExceptionHandler(AppException e) {

        return ResponseEntity.status(e.getErrorCode().getStatus())
                .body(e.getErrorCode().name() + " " + e.getMessage());
    }
}
