package capston.busthecall.domain;

import jakarta.persistence.*;
import lombok.Getter;

@Entity
@Getter
public class Route {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "route_id")
    private Long id;
}
