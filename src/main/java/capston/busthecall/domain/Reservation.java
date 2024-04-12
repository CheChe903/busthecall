package capston.busthecall.domain;


import capston.busthecall.domain.Status.DoingStatus;
import jakarta.persistence.*;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;

@Entity
@Getter
@NoArgsConstructor
public class Reservation {


    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name ="reservation_id")
    private Long id;

    @OneToOne
    @JoinColumn(name = "member_id")
    private Member member;


    @ManyToOne
    @JoinColumn(name = "bus_id")
    private Bus bus;


    private Long station_id;

    @CreationTimestamp
    @Column(name = "reserveTime")
    private LocalDateTime reserveTime;

    @Enumerated(EnumType.STRING)
    private DoingStatus status;

    @Builder
    public Reservation(Member member, Bus bus, LocalDateTime reserveTime, Long station_id, DoingStatus status)
    {
        this.member =member;
        this.bus = bus;
        this.reserveTime = reserveTime;
        this.station_id = station_id;
        this.status = status;
    }

}
