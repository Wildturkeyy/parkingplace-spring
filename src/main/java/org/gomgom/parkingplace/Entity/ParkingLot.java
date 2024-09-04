package org.gomgom.parkingplace.Entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;
import org.gomgom.parkingplace.enums.Bool;
import org.hibernate.annotations.ColumnDefault;
import org.hibernate.annotations.DynamicInsert;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDateTime;
import java.time.LocalTime;

@Getter
@Setter
@Entity
@Table(name = "tbl_parking_lot")
@DynamicInsert
@EntityListeners(AuditingEntityListener.class)
public class ParkingLot {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "parking_lot_id", nullable = false)
    private Long id;

    @Size(max = 50)
    @NotNull
    @Column(name = "parking_center_id")
    private String parkingCenterId;

    @Size(max = 100)
    @NotNull
    @Column(name = "name", nullable = false, length = 100)
    private String name;

    @Size(max = 300)
    @NotNull
    @Column(name = "address", nullable = false, length = 300)
    private String address;

    @NotNull
    @Column(name = "wash", nullable = false)
    private Character wash;

    @NotNull
    @Column(name = "maintenance", nullable = false)
    private Character maintenance;

    @Column(name = "latitude")
    private Integer latitude;

    @Column(name = "longtitude")
    private Integer longtitude;

    @Column(name = "weekdays_open_time")
    private LocalTime weekdaysOpenTime;

    @Column(name = "weekdays_close_time")
    private LocalTime weekdaysCloseTime;

    @Column(name = "weekend_open_time")
    private LocalTime weekendOpenTime;

    @Column(name = "weekend_close_time")
    private LocalTime weekendCloseTime;

    @NotNull
    @Enumerated(EnumType.STRING)
    @ColumnDefault("'N'")
    @Column(name = "usable", nullable = false)
    private Bool usable;

    @NotNull
    @CreatedDate
    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    @LastModifiedDate
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    //ManyToOne에서 OneToOne으로 변경
    @OneToOne(fetch = FetchType.LAZY, optional = true)
    @JoinColumn(name = "user_id", nullable = true)
    private User user;
}