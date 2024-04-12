package capston.busthecall.domain;


import jakarta.persistence.*;

import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;

@Entity
@Getter
@NoArgsConstructor
public class Bus {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "bus_id")
    private Long id;

    @OneToOne
    @JoinColumn(name = "driver_id")
    private Driver driver;

    private Long route_id;

    private Long station_id;

    private int remainSec;

    private int boardNum;


    @Builder
    public Bus(Driver driver, Long route_id, Long station_id, int remainSec, int boardNum) {
        this.driver = driver;
        this.route_id = route_id;
        this.station_id = station_id;
        this.remainSec = remainSec;
        this.boardNum = boardNum;
    }
}
