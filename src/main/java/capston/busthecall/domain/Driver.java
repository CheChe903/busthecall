package capston.busthecall.domain;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Getter
@NoArgsConstructor
public class Driver {

    @Id
    @GeneratedValue
    @Column(name = "driver_id")
    private Long id;

    private String name;
    private String email;
    private String password;
    private String role;

    @OneToOne(mappedBy = "driver", fetch = FetchType.LAZY)
    private Bus bus;

}
