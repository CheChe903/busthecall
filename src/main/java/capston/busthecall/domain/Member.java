package capston.busthecall.domain;


import capston.busthecall.domain.Status.BoardingStatus;
import jakarta.persistence.*;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Getter
@NoArgsConstructor
public class Member {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name ="member_id")
    private Long id;

    private String password;
    private String name;
    private String phoneNumber;

    @Column(unique = true)
    private String email;

    @Enumerated(EnumType.STRING)
    private BoardingStatus status;


    public boolean isPassword(String target)
    {
        return password.equals(target);
    }
    @Builder
    public Member(String name, String password, String phoneNumber, String email, BoardingStatus status
    ) {
        this.name =name;
        this.password =password;
        this.phoneNumber=phoneNumber;
        this.email =email;
        this.status = status;

    }

    @Column(nullable = false)
    private Boolean deleted = false;

    public void delete() {
        this.deleted = true;
    }
}
